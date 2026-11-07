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
	c                    *http.Client
}

func NewTransit(addr, token string) *Transit {
	return &Transit{Addr: addr, Token: token, KeyName: "sealed-logs-master", c: &http.Client{Timeout: 5 * time.Second}}
}

func (t *Transit) Name() string { return "openbao-transit" }

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
	err := t.do(ctx, "/v1/transit/encrypt/"+t.KeyName, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(key),
		"context":   base64.StdEncoding.EncodeToString([]byte(project)),
	}, &out)
	return out.Data.Ciphertext, err
}

func (t *Transit) Unwrap(ctx context.Context, project, blob string) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err := t.do(ctx, "/v1/transit/decrypt/"+t.KeyName, map[string]any{
		"ciphertext": blob,
		"context":    base64.StdEncoding.EncodeToString([]byte(project)),
	}, &out)
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
		return fmt.Errorf("openbao %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if out != nil && len(rb) > 0 {
		return json.Unmarshal(rb, out)
	}
	return nil
}
