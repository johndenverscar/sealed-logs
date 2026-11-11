// aggregator answers log queries and live tails. It narrows by the ClickHouse
// index, fetches sealed chunks (or reads them off the stream, for a tail), and
// asks keysvc to unwrap day keys using the caller's own token. It has no standing
// key access: keysvc decides who gets plaintext.
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
	"github.com/twmb/franz-go/pkg/kgo"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
	"sealedlogs/internal/envelope"
	"sealedlogs/internal/events"
	"sealedlogs/internal/stream"
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

	kafka *kgo.Client // admin and end-offset lookups for tails

	mu    sync.Mutex
	cache map[string]cached // caller subject + key_id
	tails map[chan notice]bool
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

// outChunk describes one chunk the index matched. The metadata fields come from
// the index row, so a caller who can't decrypt still sees when and where the
// chunk was written, and nothing of what it says.
type outChunk struct {
	ChunkID   string            `json:"chunk_id"`
	KeyID     string            `json:"key_id"`
	Session   string            `json:"session_id"`
	Source    string            `json:"source"`
	TSMin     time.Time         `json:"ts_min"`
	TSMax     time.Time         `json:"ts_max"`
	Lines     uint32            `json:"lines"`
	Levels    map[string]uint32 `json:"levels"`
	Status    string            `json:"status"`
	Reason    string            `json:"reason,omitempty"`
	CTPreview string            `json:"ct_preview,omitempty"`
	CTBytes   int               `json:"ct_bytes"`
}

func main() {
	ch, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{config.CHAddr},
		Auth: clickhouse.Auth{Database: "default", Username: config.CHUser, Password: config.CHPass},
	})
	must(err)
	mc, err := minio.New(config.MinioEndpoint, &minio.Options{Creds: credentials.NewStaticV4(config.MinioUser, config.MinioPass, "")})
	must(err)

	kc, err := stream.NewClient()
	must(err)
	s := &server{ch: ch, store: mc, kafka: kc, http: &http.Client{Timeout: 5 * time.Second},
		cache: map[string]cached{}, tails: map[chan notice]bool{}}
	go s.followRevocations()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /logs", s.logs)
	mux.HandleFunc("GET /tail", s.tail)

	addr := config.Env("AGGREGATOR_ADDR", "127.0.0.1:7103")
	log.Printf("aggregator on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// filter is a query's narrowing: the project, a time range, and optionally a
// session, a minimum level and text to match after decryption.
type filter struct {
	project, session, needle string
	minLevel                 int
}

func parseFilter(q map[string][]string) filter {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	return filter{project: get("project"), session: get("session"), needle: get("q"), minLevel: levelRank(get("level"))}
}

// idx is one index row: everything storage knows about a chunk without its key.
type idx struct {
	chunkID, keyID, objectKey, session, source string
	tsMin, tsMax                               time.Time
	lines, nDebug, nInfo, nWarn, nError        uint32
}

func idxFromMeta(m envelope.Meta, objectKey string) idx {
	return idx{chunkID: m.ChunkID, keyID: m.KeyID, objectKey: objectKey, session: m.SessionID, source: m.Source,
		tsMin: m.TSMin, tsMax: m.TSMax, lines: m.Lines,
		nDebug: m.Levels["debug"], nInfo: m.Levels["info"], nWarn: m.Levels["warn"], nError: m.Levels["error"]}
}

func (f filter) wants(x idx) bool {
	switch {
	case x.keyID == "" || !strings.HasPrefix(x.keyID, f.project+"/"):
		return false
	case f.session != "" && x.session != f.session:
		return false
	case f.minLevel == 3 && x.nError == 0, f.minLevel == 2 && x.nWarn+x.nError == 0:
		return false
	}
	return true
}

// query reads the index for chunks overlapping [from, to]. With ingestedAfter
// set, only chunks indexed after it (a tail's backfill).
func (s *server) query(ctx context.Context, f filter, from, to, ingestedAfter time.Time) ([]idx, error) {
	sqlq := `SELECT chunk_id, key_id, object_key, session_id, source, ts_min, ts_max, lines,
		n_debug, n_info, n_warn, n_error FROM sealed.log_chunks
		WHERE project = ? AND ts_max >= ? AND ts_min <= ?`
	args := []any{f.project, from, to}
	if !ingestedAfter.IsZero() {
		sqlq += " AND ingested_at > ?"
		args = append(args, ingestedAfter)
	}
	if f.session != "" {
		sqlq += " AND session_id = ?"
		args = append(args, f.session)
	}
	switch f.minLevel {
	case 3:
		sqlq += " AND n_error > 0"
	case 2:
		sqlq += " AND n_warn + n_error > 0"
	}
	sqlq += " ORDER BY ts_min DESC LIMIT 500"
	rows, err := s.ch.Query(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hits []idx
	seen := map[string]bool{} // a retried upload can index the same chunk twice
	for rows.Next() {
		var x idx
		err := rows.Scan(&x.chunkID, &x.keyID, &x.objectKey, &x.session, &x.source, &x.tsMin, &x.tsMax, &x.lines,
			&x.nDebug, &x.nInfo, &x.nWarn, &x.nError)
		if err == nil && !seen[x.chunkID] {
			seen[x.chunkID] = true
			hits = append(hits, x)
		}
	}
	return hits, nil
}

// open decrypts one chunk for the caller, if keysvc lets them, and returns what
// they may see. raw is the stored body when the caller already has it (a tail
// reading the stream); otherwise it is fetched from the bucket.
func (s *server) open(ctx context.Context, c *auth.Claims, tok string, h idx, raw []byte, f filter, reqID, via string) (outChunk, []outLine) {
	oc := outChunk{ChunkID: h.chunkID, KeyID: h.keyID, Session: h.session, Source: h.source,
		TSMin: h.tsMin, TSMax: h.tsMax, Lines: h.lines,
		Levels: map[string]uint32{"debug": h.nDebug, "info": h.nInfo, "warn": h.nWarn, "error": h.nError}}
	var ck envelope.Chunk
	var err error
	if raw == nil {
		ck, raw, err = s.fetch(ctx, h.objectKey)
	} else {
		err = json.Unmarshal(raw, &ck)
	}
	oc.CTBytes = len(raw)
	if err != nil {
		oc.Status, oc.Reason = "error", err.Error()
		return oc, nil
	}
	oc.CTPreview = events.Preview(ck.Sealed.CT, 16)

	var lines []outLine
	k := s.key(ctx, c, tok, h.keyID)
	oc.Status, oc.Reason = k.status, k.reason
	if k.status == "decrypted" {
		ls, err := envelope.Open(k.priv, ck.Meta, ck.Sealed)
		if err != nil {
			oc.Status, oc.Reason = "error", "open: "+err.Error()
		} else {
			oc.CTPreview = ""
			for _, l := range ls {
				if levelRank(l.Level) >= f.minLevel && matches(l.Msg, f.needle) {
					lines = append(lines, outLine{TS: l.TS, Level: l.Level, Msg: l.Msg, Session: h.session, ChunkID: h.chunkID, Stream: l.Stream, Attrs: l.Attrs})
				}
			}
		}
	}
	events.Emit("aggregator", "chunk", map[string]any{
		"request_id": reqID, "chunk_id": h.chunkID, "key_id": h.keyID, "status": oc.Status, "via": via,
		"reason": oc.Reason, "sub": c.Subject, "role": c.Role, "key_cache": k.hit, "object_bytes": len(raw),
	})
	return oc, lines
}

func (s *server) logs(w http.ResponseWriter, r *http.Request) {
	c, tok, err := auth.FromRequest(r)
	if err != nil {
		httpErr(w, 401, "invalid token")
		return
	}
	q := r.URL.Query()
	f := parseFilter(q)
	if f.project == "" {
		httpErr(w, 400, "project is required")
		return
	}
	since, err := time.ParseDuration(defaultStr(q.Get("since"), "24h"))
	if err != nil {
		httpErr(w, 400, "bad since")
		return
	}
	limit, _ := strconv.Atoi(defaultStr(q.Get("limit"), "200"))
	reqID := "q_" + randHex(4)
	to := time.Now().UTC()
	from := to.Add(-since)

	hits, err := s.query(r.Context(), f, from, to, time.Time{})
	if err != nil {
		httpErr(w, 502, "clickhouse: "+err.Error())
		return
	}
	events.Emit("aggregator", "index_query", map[string]any{
		"request_id": reqID, "sub": c.Subject, "role": c.Role, "caller_project": c.Project, "project": f.project,
		"session": f.session, "from": from, "to": to, "chunks": len(hits),
	})

	var lines []outLine
	var chunks []outChunk
	for _, h := range hits {
		oc, ls := s.open(r.Context(), c, tok, h, nil, f, reqID, "bucket")
		chunks = append(chunks, oc)
		lines = append(lines, ls...)
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

// tail streams new chunks to the caller as server-sent events, decrypted with
// the caller's own token, exactly as /logs would. It pins the stream's end
// offset first, then backfills from the index anything stored after the
// caller's last read, so nothing falls in the gap. Chunks are deduplicated by ID.
func (s *server) tail(w http.ResponseWriter, r *http.Request) {
	c, tok, err := auth.FromRequest(r)
	if err != nil {
		httpErr(w, 401, "invalid token")
		return
	}
	q := r.URL.Query()
	f := parseFilter(q)
	if f.project == "" {
		httpErr(w, 400, "project is required")
		return
	}
	after, err := time.Parse(time.RFC3339Nano, q.Get("after"))
	if err != nil {
		after = time.Now().UTC().Add(-time.Minute)
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		httpErr(w, 500, "streaming unsupported")
		return
	}
	ctx := r.Context()
	offsets, err := stream.EndOffsets(ctx, s.kafka)
	if err != nil {
		httpErr(w, 502, "stream: "+err.Error())
		return
	}
	cl, err := stream.NewClient(kgo.ConsumePartitions(offsets))
	if err != nil {
		httpErr(w, 502, "stream: "+err.Error())
		return
	}
	defer cl.Close()
	notices := s.subscribe()
	defer s.unsubscribe(notices)

	reqID := "t_" + randHex(4)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	send := func(event string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		fl.Flush()
	}
	started := time.Now()
	events.Emit("aggregator", "tail_started", map[string]any{
		"request_id": reqID, "sub": c.Subject, "role": c.Role, "project": f.project, "session": f.session, "after": after,
	})
	send("hello", map[string]any{"request_id": reqID, "caller": map[string]string{"sub": c.Subject, "role": c.Role, "project": c.Project}})

	seen := map[string]bool{}
	deliver := func(h idx, raw []byte, via string) {
		if seen[h.chunkID] || !f.wants(h) {
			return
		}
		seen[h.chunkID] = true
		oc, ls := s.open(ctx, c, tok, h, raw, f, reqID, via)
		send("chunk", map[string]any{"chunk": oc, "lines": ls, "via": via})
	}

	if hits, err := s.query(ctx, f, after.Add(-time.Hour), time.Now().UTC().Add(time.Minute), after); err == nil {
		for i := len(hits) - 1; i >= 0; i-- { // oldest first
			deliver(hits[i], nil, "backfill")
		}
	}

	recs := make(chan *kgo.Record)
	go func() {
		defer close(recs)
		for {
			fs := cl.PollFetches(ctx)
			if ctx.Err() != nil {
				return
			}
			fs.EachRecord(func(rec *kgo.Record) {
				select {
				case recs <- rec:
				case <-ctx.Done():
				}
			})
		}
	}()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			events.Emit("aggregator", "tail_ended", map[string]any{
				"request_id": reqID, "sub": c.Subject, "role": c.Role, "chunks": len(seen), "seconds": int(time.Since(started).Seconds()),
			})
			return
		case rec, ok := <-recs:
			if !ok {
				continue
			}
			var m stream.Message
			var ck envelope.Chunk
			if json.Unmarshal(rec.Value, &m) != nil || json.Unmarshal(m.Chunk, &ck) != nil {
				continue
			}
			deliver(idxFromMeta(ck.Meta, m.ObjectKey), m.Chunk, "stream")
		case n := <-notices:
			// A key was destroyed or someone's access ended: the caller's view of
			// what they already have may be out of date.
			send("revoked", n)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

type notice struct {
	KeyID   string `json:"key_id,omitempty"`
	Sub     string `json:"sub,omitempty"`
	Project string `json:"project,omitempty"` // the project's own key became unavailable, or came back
}

func (s *server) subscribe() chan notice {
	ch := make(chan notice, 16)
	s.mu.Lock()
	s.tails[ch] = true
	s.mu.Unlock()
	return ch
}

func (s *server) unsubscribe(ch chan notice) {
	s.mu.Lock()
	delete(s.tails, ch)
	s.mu.Unlock()
}

// followRevocations evicts cached keys as soon as keysvc destroys them, every
// decision cached for a person whose access grant started or ended, and every
// key of a project whose own KMS key went away or came back. Open tails are
// told too.
func (s *server) followRevocations() {
	after := 0
	for ; ; time.Sleep(revocationPoll) {
		resp, err := s.http.Get(fmt.Sprintf("%s/revocations?after=%d", config.KeysvcURL, after))
		if err != nil {
			continue
		}
		var revs []struct {
			Seq     int    `json:"seq"`
			KeyID   string `json:"key_id"`
			Sub     string `json:"sub"`
			Project string `json:"project"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&revs)
		resp.Body.Close()
		for _, r := range revs {
			after = r.Seq
			s.mu.Lock()
			for k, v := range s.cache {
				if (r.KeyID != "" && strings.HasSuffix(k, "|"+r.KeyID)) || (r.Sub != "" && strings.HasPrefix(k, r.Sub+"|")) ||
					(r.Project != "" && strings.Contains(k, "|"+r.Project+"/")) {
					clear(v.priv)
					delete(s.cache, k)
				}
			}
			for ch := range s.tails {
				select {
				case ch <- notice{KeyID: r.KeyID, Sub: r.Sub, Project: r.Project}:
				default:
				}
			}
			s.mu.Unlock()
			switch {
			case r.KeyID != "":
				events.Emit("aggregator", "key_evicted", map[string]any{"key_id": r.KeyID})
			case r.Sub != "":
				events.Emit("aggregator", "access_evicted", map[string]any{"sub": r.Sub})
			default:
				events.Emit("aggregator", "project_evicted", map[string]any{"project": r.Project})
			}
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
		Priv    []byte    `json:"priv"`
		Expires time.Time `json:"expires_at"`
		Error   string    `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	switch resp.StatusCode {
	case 200:
		v.status, v.priv = "decrypted", out.Priv
		if !out.Expires.IsZero() && out.Expires.Before(v.expires) {
			v.expires = out.Expires // a time-boxed grant: never cache past its end
		}
	case 403:
		v.status, v.reason = "denied", out.Error
	case 410:
		v.status, v.reason = "destroyed", out.Error
	case 423:
		v.status, v.reason = "locked", out.Error
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
