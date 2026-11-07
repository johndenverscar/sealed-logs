// aggregator answers log queries. It narrows by the ClickHouse index, fetches sealed
// chunks, and asks keysvc to unwrap day keys using the caller's own token. It has
// no standing key access: keysvc decides who gets plaintext.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
	"sealedlogs/internal/envelope"
	"sealedlogs/internal/events"
)

const keyCacheTTL = 5 * time.Minute

const revocationPoll = 2 * time.Second

type cached struct {
	priv    []byte
	hit     bool
	status  string
	reason  string
	expires time.Time
}

type server struct {
	ch    driver.Conn
	store *minio.Client
	http  *http.Client

	mu    sync.Mutex
	cache map[string]cached // caller subject + key_id
}

type outLine struct {
	TS      time.Time         `json:"ts"`
	Level   string            `json:"level"`
	Msg     string            `json:"msg"`
	Session string            `json:"session_id"`
	ChunkID string            `json:"chunk_id"`
	Stream  string            `json:"stream,omitempty"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

type outChunk struct {
	ChunkID   string `json:"chunk_id"`
	KeyID     string `json:"key_id"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	CTPreview string `json:"ct_preview,omitempty"`
	CTBytes   int    `json:"ct_bytes"`
}

func main() {
	ch, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{config.CHAddr},
		Auth: clickhouse.Auth{Database: "default", Username: config.CHUser, Password: config.CHPass},
	})
	must(err)
	mc, err := minio.New(config.MinioEndpoint, &minio.Options{Creds: credentials.NewStaticV4(config.MinioUser, config.MinioPass, "")})
	must(err)

	s := &server{ch: ch, store: mc, http: &http.Client{Timeout: 5 * time.Second}, cache: map[string]cached{}}
	go s.followRevocations()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /logs", s.logs)

	addr := config.Env("AGGREGATOR_ADDR", "127.0.0.1:7103")
	log.Printf("aggregator on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (s *server) logs(w http.ResponseWriter, r *http.Request) {
	c, tok, err := auth.FromRequest(r)
	if err != nil {
		httpErr(w, 401, "invalid token")
		return
	}
	q := r.URL.Query()
	project := q.Get("project")
	if project == "" {
		httpErr(w, 400, "project is required")
		return
	}
	since, err := time.ParseDuration(defaultStr(q.Get("since"), "24h"))
	if err != nil {
		httpErr(w, 400, "bad since")
		return
	}
	limit, _ := strconv.Atoi(defaultStr(q.Get("limit"), "200"))
	minLevel := levelRank(q.Get("level"))
	needle := q.Get("q")
	reqID := "q_" + randHex(4)
	to := time.Now().UTC()
	from := to.Add(-since)

	sqlq := `SELECT chunk_id, key_id, object_key, session_id FROM sealed.log_chunks
		WHERE project = ? AND ts_max >= ? AND ts_min <= ?`
	args := []any{project, from, to}
	if sess := q.Get("session"); sess != "" {
		sqlq += " AND session_id = ?"
		args = append(args, sess)
	}
	switch minLevel {
	case 3:
		sqlq += " AND n_error > 0"
	case 2:
		sqlq += " AND n_warn + n_error > 0"
	}
	sqlq += " ORDER BY ts_min DESC LIMIT 500"

	rows, err := s.ch.Query(r.Context(), sqlq, args...)
	if err != nil {
		httpErr(w, 502, "clickhouse: "+err.Error())
		return
	}
	type idx struct{ chunkID, keyID, objectKey, session string }
	var hits []idx
	for rows.Next() {
		var x idx
		if err := rows.Scan(&x.chunkID, &x.keyID, &x.objectKey, &x.session); err == nil {
			hits = append(hits, x)
		}
	}
	rows.Close()
	events.Emit("aggregator", "index_query", map[string]any{
		"request_id": reqID, "sub": c.Subject, "role": c.Role, "caller_project": c.Project, "project": project,
		"session": q.Get("session"), "from": from, "to": to, "chunks": len(hits),
	})

	var lines []outLine
	var chunks []outChunk
	for _, h := range hits {
		ck, raw, err := s.fetch(r.Context(), h.objectKey)
		oc := outChunk{ChunkID: h.chunkID, KeyID: h.keyID, CTBytes: len(raw)}
		if err != nil {
			oc.Status, oc.Reason = "error", err.Error()
			chunks = append(chunks, oc)
			continue
		}
		oc.CTPreview = events.Preview(ck.Sealed.CT, 16)

		k := s.key(r.Context(), c, tok, h.keyID)
		oc.Status, oc.Reason = k.status, k.reason
		if k.status == "decrypted" {
			ls, err := envelope.Open(k.priv, ck.Meta, ck.Sealed)
			if err != nil {
				oc.Status, oc.Reason = "error", "open: "+err.Error()
			} else {
				oc.CTPreview = ""
				for _, l := range ls {
					if levelRank(l.Level) >= minLevel && matches(l.Msg, needle) {
						lines = append(lines, outLine{TS: l.TS, Level: l.Level, Msg: l.Msg, Session: h.session, ChunkID: h.chunkID, Stream: l.Stream, Attrs: l.Attrs})
					}
				}
			}
		}
		events.Emit("aggregator", "chunk", map[string]any{
			"request_id": reqID, "chunk_id": h.chunkID, "key_id": h.keyID, "status": oc.Status,
			"reason": oc.Reason, "sub": c.Subject, "role": c.Role, "key_cache": k.hit, "object_bytes": len(raw),
		})
		chunks = append(chunks, oc)
	}

	sort.Slice(lines, func(i, j int) bool { return lines[i].TS.After(lines[j].TS) })
	if len(lines) > limit {
		lines = lines[:limit]
	}
	events.Emit("aggregator", "response", map[string]any{
		"request_id": reqID, "sub": c.Subject, "role": c.Role, "lines": len(lines), "chunks": len(chunks),
	})
	writeJSON(w, 200, map[string]any{
		"request_id": reqID,
		"caller":     map[string]string{"sub": c.Subject, "role": c.Role, "project": c.Project},
		"chunks":     chunks,
		"lines":      lines,
	})
}

// followRevocations evicts cached keys as soon as keysvc destroys them.
func (s *server) followRevocations() {
	after := 0
	for ; ; time.Sleep(revocationPoll) {
		resp, err := s.http.Get(fmt.Sprintf("%s/revocations?after=%d", config.KeysvcURL, after))
		if err != nil {
			continue
		}
		var revs []struct {
			Seq   int    `json:"seq"`
			KeyID string `json:"key_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&revs)
		resp.Body.Close()
		for _, r := range revs {
			after = r.Seq
			s.mu.Lock()
			for k, v := range s.cache {
				if strings.HasSuffix(k, "|"+r.KeyID) {
					clear(v.priv)
					delete(s.cache, k)
				}
			}
			s.mu.Unlock()
			events.Emit("aggregator", "key_evicted", map[string]any{"key_id": r.KeyID})
		}
	}
}

func (s *server) fetch(ctx context.Context, objectKey string) (envelope.Chunk, []byte, error) {
	var ck envelope.Chunk
	obj, err := s.store.GetObject(ctx, config.Bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return ck, nil, err
	}
	defer obj.Close()
	raw, err := io.ReadAll(obj)
	if err != nil {
		return ck, nil, err
	}
	return ck, raw, json.Unmarshal(raw, &ck)
}

// key unwraps through keysvc with the caller's token and caches the result per
// caller, so one person's access never serves another.
func (s *server) key(ctx context.Context, c *auth.Claims, tok, keyID string) cached {
	ck := c.Subject + "|" + keyID
	s.mu.Lock()
	if v, ok := s.cache[ck]; ok && time.Now().Before(v.expires) {
		s.mu.Unlock()
		v.hit = true
		return v
	}
	s.mu.Unlock()

	body, _ := json.Marshal(map[string]string{"key_id": keyID})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, config.KeysvcURL+"/unwrap", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	v := cached{expires: time.Now().Add(keyCacheTTL)}
	resp, err := s.http.Do(req)
	if err != nil {
		return cached{status: "error", reason: err.Error()}
	}
	defer resp.Body.Close()
	var out struct {
		Priv  []byte `json:"priv"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	switch resp.StatusCode {
	case 200:
		v.status, v.priv = "decrypted", out.Priv
	case 403:
		v.status, v.reason = "denied", out.Error
	case 410:
		v.status, v.reason = "destroyed", out.Error
	default:
		return cached{status: "error", reason: fmt.Sprintf("keysvc %d %s", resp.StatusCode, out.Error)}
	}
	s.mu.Lock()
	s.cache[ck] = v
	s.mu.Unlock()
	return v
}

// matches does a case-insensitive substring match, and for all-digit needles also
// matches with every non-digit stripped from the line. Search can see through
// "4🙂1🙂1🙂1" because it runs on plaintext after decryption.
func matches(msg, needle string) bool {
	if needle == "" {
		return true
	}
	if strings.Contains(strings.ToLower(msg), strings.ToLower(needle)) {
		return true
	}
	if strings.IndexFunc(needle, func(r rune) bool { return !unicode.IsDigit(r) && r != ' ' }) == -1 {
		return strings.Contains(digits(msg), digits(needle))
	}
	return false
}

func digits(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, s)
}

func levelRank(l string) int {
	switch strings.ToLower(l) {
	case "error":
		return 3
	case "warn", "warning":
		return 2
	case "info":
		return 1
	}
	return 0
}

func defaultStr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
