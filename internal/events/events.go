// Package events writes lifecycle events as JSON lines on stdout, tagged so the
// TUI can pick them out of `kubectl logs`. Events never carry log text; the
// observer must not become a plaintext copy.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Tag marks a stdout line as an event.
const Tag = "sealedlogs/v1"

var mu sync.Mutex

func Emit(stage, kind string, fields map[string]any) {
	id := make([]byte, 6)
	_, _ = rand.Read(id)
	e := map[string]any{"ev": Tag, "id": hex.EncodeToString(id), "ts": time.Now().UTC().Format(time.RFC3339Nano), "stage": stage, "kind": kind}
	for k, v := range fields {
		e[k] = v
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	_, _ = os.Stdout.Write(append(b, '\n'))
}

func Preview(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return hex.EncodeToString(b)
}
