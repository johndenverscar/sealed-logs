package main

// The customer's side of a customer-managed key. The demo server plays the
// customer here: it holds their KMS's root token, creates their key, and decides
// what the operator's keysvc may do with it. keysvc only ever gets a scoped token.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
)

const (
	customerKeyName = "p_demo-logs"
	operatorPolicy  = "operator-keysvc"
)

// policyFor is the customer's KMS policy for the operator's keysvc. Encrypt stays
// allowed either way, so logs keep flowing; decrypt is what the customer gives
// and takes away.
func policyFor(decrypt bool) string {
	p := fmt.Sprintf("path \"transit/encrypt/%s\" { capabilities = [\"update\"] }\n", customerKeyName)
	if decrypt {
		p += fmt.Sprintf("path \"transit/decrypt/%s\" { capabilities = [\"update\"] }\n", customerKeyName)
	}
	return p
}

func customerKMS(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, config.CustomerKMSAddr+path, rd)
	req.Header.Set("X-Vault-Token", config.CustomerKMSToken)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("customer KMS %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

func setPolicy(decrypt bool) error {
	return customerKMS(http.MethodPut, "/v1/sys/policies/acl/"+operatorPolicy, map[string]string{"policy": policyFor(decrypt)}, nil)
}

// enableBYOK creates the customer's key and a token for keysvc in the customer's
// KMS, then asks keysvc, as a project admin, to switch the project over.
func enableBYOK(w http.ResponseWriter, r *http.Request) {
	as := viewer(r.URL.Query().Get("as"))
	err := customerKMS(http.MethodPost, "/v1/sys/mounts/transit", map[string]string{"type": "transit"}, nil)
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		jsonErr(w, err)
		return
	}
	if err := customerKMS(http.MethodPost, "/v1/transit/keys/"+customerKeyName, map[string]any{}, nil); err != nil && !strings.Contains(err.Error(), "exists") {
		jsonErr(w, err)
		return
	}
	if err := setPolicy(true); err != nil {
		jsonErr(w, err)
		return
	}
	var tok struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := customerKMS(http.MethodPost, "/v1/auth/token/create", map[string]any{
		"policies": []string{operatorPolicy}, "no_default_policy": true, "ttl": "720h", "display_name": "operator-keysvc",
	}, &tok); err != nil {
		jsonErr(w, err)
		return
	}
	b, _ := json.Marshal(map[string]string{"kms_addr": config.CustomerKMSAddr, "key_name": customerKeyName, "token": tok.Auth.ClientToken})
	keysvc(w, http.MethodPut, "/projects/"+url.PathEscape(config.DemoProject)+"/byok", as, bytes.NewReader(b))
}

// customerDecrypt is the customer, in their own KMS, taking decrypt away from the
// operator or giving it back. keysvc isn't asked; it notices.
func customerDecrypt(allow bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if err := setPolicy(allow); err != nil {
			jsonErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"decrypt": allow, "policy": policyFor(allow)})
	}
}

// byokState is keysvc's view of the project's key next to the customer's policy.
func byokState(w http.ResponseWriter, r *http.Request) {
	as := viewer(r.URL.Query().Get("as"))
	out := map[string]any{}
	req, _ := http.NewRequest(http.MethodGet, config.KeysvcURL+"/projects/"+url.PathEscape(config.DemoProject)+"/byok", nil)
	req.Header.Set("Authorization", "Bearer "+auth.DemoToken(as))
	if resp, err := http.DefaultClient.Do(req); err == nil {
		var ks map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&ks)
		resp.Body.Close()
		out["keysvc"] = ks
	}
	var pol struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if customerKMS(http.MethodGet, "/v1/sys/policies/acl/"+operatorPolicy, nil, &pol) == nil {
		out["policy"] = pol.Data.Policy
		out["decrypt"] = strings.Contains(pol.Data.Policy, "transit/decrypt/")
	}
	writeJSON(w, out)
}

// accessLog is keysvc's access log for the demo project, as the chosen identity.
func accessLog(w http.ResponseWriter, r *http.Request) {
	keysvc(w, http.MethodGet, "/access-log?project="+url.QueryEscape(config.DemoProject), viewer(r.URL.Query().Get("as")), nil)
}

func jsonErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	writeJSON(w, map[string]string{"error": err.Error()})
}
