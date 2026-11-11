// Package wrap hides the master-key backend behind one interface so keysvc stays
// cloud agnostic. OpenBao Transit is the default; OCI/AWS/GCP/Azure KMS would be
// further implementations.
package wrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type KeyWrapper interface {
	Name() string
	Wrap(ctx context.Context, project string, key []byte) (string, error)
	Unwrap(ctx context.Context, project, blob string) ([]byte, error)
}

// Transit uses one derived transit key; the project ID is the derivation context,
// so each project effectively has its own master key.
type Transit struct {
	Addr, Token, KeyName string
	Derived              bool
	name                 string
	c                    *http.Client
}

func NewTransit(addr, token string) *Transit {
	return &Transit{Addr: addr, Token: token, KeyName: "sealed-logs-master", Derived: true, name: "openbao-transit",
		c: &http.Client{Timeout: 5 * time.Second}}
}

// NewCustomerKey wraps with a key in the customer's own KMS, through a token the
// customer issued. The customer can take decrypt away from that token at any
// time; from then on nothing wrapped with the key can be unwrapped.
func NewCustomerKey(addr, token, keyName string) *Transit {
	return &Transit{Addr: addr, Token: token, KeyName: keyName, name: "customer-kms", c: &http.Client{Timeout: 3 * time.Second}}
}

func (t *Transit) Name() string { return t.name }

func (t *Transit) context(project string) map[string]any {
	if !t.Derived {
		return map[string]any{}
	}
	return map[string]any{"context": base64.StdEncoding.EncodeToString([]byte(project))}
}

func (t *Transit) Init(ctx context.Context) error {
	err := t.do(ctx, "/v1/sys/mounts/transit", map[string]any{"type": "transit"}, nil)
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return err
	}
	err = t.do(ctx, "/v1/transit/keys/"+t.KeyName, map[string]any{"derived": true}, nil)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

func (t *Transit) Wrap(ctx context.Context, project string, key []byte) (string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	body := t.context(project)
	body["plaintext"] = base64.StdEncoding.EncodeToString(key)
	err := t.do(ctx, "/v1/transit/encrypt/"+t.KeyName, body, &out)
	return out.Data.Ciphertext, err
}

func (t *Transit) Unwrap(ctx context.Context, project, blob string) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	body := t.context(project)
	body["ciphertext"] = blob
	err := t.do(ctx, "/v1/transit/decrypt/"+t.KeyName, body, &out)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Data.Plaintext)
}

func (t *Transit) do(ctx context.Context, path string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Addr+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", t.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(rb))
		var e struct{ Errors []string }
		if json.Unmarshal(rb, &e) == nil && len(e.Errors) > 0 {
			msg = strings.Join(strings.Fields(strings.Join(e.Errors, "; ")), " ")
		}
		return fmt.Errorf("%s %s: %d %s", t.name, path, resp.StatusCode, msg)
	}
	if out != nil && len(rb) > 0 {
		return json.Unmarshal(rb, out)
	}
	return nil
}
