// keysvc issues one key pair per project per day, wraps private keys with the
// master-key backend, and unwraps only for members of the key's own project.
// Every unwrap, denial, purge and expiry is audited.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
	"sealedlogs/internal/envelope"
	"sealedlogs/internal/events"
	"sealedlogs/internal/wrap"
)

const dayFmt = "2006-01-02"

type server struct {
	db        *sql.DB
	wrapper   wrap.KeyWrapper
	sign      ed25519.PrivateKey
	allowPast bool
	retention int
	mu        sync.Mutex
}

func main() {
	ctx := context.Background()
	_ = os.MkdirAll(config.Var(""), 0o755)

	db, err := sql.Open("sqlite", config.Var("keysvc.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	must(err)
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS keys(
  key_id TEXT PRIMARY KEY, project TEXT, day TEXT, gen INTEGER,
  pub BLOB, sig BLOB, wrapped TEXT, created_at TEXT, destroyed_at TEXT, destroy_reason TEXT);
CREATE TABLE IF NOT EXISTS revocations(seq INTEGER PRIMARY KEY AUTOINCREMENT, key_id TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, sub TEXT, caller_project TEXT, role TEXT,
  key_id TEXT, action TEXT, allowed INTEGER, reason TEXT);`)
	must(err)

	tr := wrap.NewTransit(config.BaoAddr, config.BaoToken)
	must(tr.Init(ctx))

	retention, _ := strconv.Atoi(config.Env("RETENTION_DAYS", "7"))
	s := &server{db: db, wrapper: tr, sign: loadSigningKey(), allowPast: os.Getenv("DEMO_ALLOW_PAST") == "1", retention: retention}

	go s.retentionLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /signing-key", s.signingKey)
	mux.HandleFunc("GET /pubkey", s.pubkey)
	mux.HandleFunc("POST /unwrap", s.unwrap)
	mux.HandleFunc("POST /purge", s.purge)
	mux.HandleFunc("GET /keys", s.list)
	mux.HandleFunc("GET /revocations", s.revocations)
	mux.HandleFunc("GET /audit", s.auditLog)

	addr := config.Env("KEYSVC_ADDR", "127.0.0.1:7101")
	log.Printf("keysvc on %s, wrapper=%s, retention=%dd", addr, tr.Name(), retention)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func loadSigningKey() ed25519.PrivateKey {
	p := config.Var("keysvc-signing.seed")
	seed, err := os.ReadFile(p)
	if err != nil || len(seed) != ed25519.SeedSize {
		seed = make([]byte, ed25519.SeedSize)
		_, _ = rand.Read(seed)
		must(os.WriteFile(p, seed, 0o600))
	}
	return ed25519.NewKeyFromSeed(seed)
}

func (s *server) signingKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"pub": []byte(s.sign.Public().(ed25519.PublicKey))})
}

type keyRow struct {
	KeyID, Project, Day string
	Gen                 int
	Pub, Sig            []byte
	Wrapped             sql.NullString
	Destroyed           sql.NullString
	Reason              sql.NullString
}

func (s *server) latest(project, day string) (*keyRow, error) {
	r := &keyRow{}
	err := s.db.QueryRow(`SELECT key_id, project, day, gen, pub, sig, wrapped, destroyed_at, destroy_reason
		FROM keys WHERE project=? AND day=? ORDER BY gen DESC LIMIT 1`, project, day).
		Scan(&r.KeyID, &r.Project, &r.Day, &r.Gen, &r.Pub, &r.Sig, &r.Wrapped, &r.Destroyed, &r.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

func (s *server) byID(keyID string) (*keyRow, error) {
	r := &keyRow{}
	err := s.db.QueryRow(`SELECT key_id, project, day, gen, pub, sig, wrapped, destroyed_at, destroy_reason
		FROM keys WHERE key_id=?`, keyID).
		Scan(&r.KeyID, &r.Project, &r.Day, &r.Gen, &r.Pub, &r.Sig, &r.Wrapped, &r.Destroyed, &r.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// pubkey returns the live public key for a project-day, creating the next
// generation if none exists or the latest was purged.
func (s *server) pubkey(w http.ResponseWriter, r *http.Request) {
	c, _, err := auth.FromRequest(r)
	project := r.URL.Query().Get("project")
	if err != nil || c.Role != auth.RoleProducer || c.Project != project {
		httpErr(w, 403, "producer token for this project required")
		return
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	day := r.URL.Query().Get("day")
	if day == "" {
		day = today.Format(dayFmt)
	}
	d, err := time.Parse(dayFmt, day)
	if err != nil {
		httpErr(w, 400, "bad day")
		return
	}
	if d.After(today.AddDate(0, 0, 1)) || (d.Before(today) && !s.allowPast) {
		httpErr(w, 400, "keys are issued for today and tomorrow only")
		return
	}
	if d.Before(today.AddDate(0, 0, -s.retention)) {
		httpErr(w, 410, "day is past retention")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	k, err := s.latest(project, day)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	if k == nil || k.Destroyed.Valid {
		gen := 1
		if k != nil {
			gen = k.Gen + 1
		}
		if k, err = s.create(r.Context(), project, day, gen); err != nil {
			httpErr(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"key_id": k.KeyID, "pub": k.Pub, "sig": k.Sig})
}

func (s *server) create(ctx context.Context, project, day string, gen int) (*keyRow, error) {
	pub, priv, err := envelope.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	keyID := fmt.Sprintf("%s/%s/g%d", project, day, gen)
	wrapped, err := s.wrapper.Wrap(ctx, project, priv)
	clear(priv)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(s.sign, envelope.SignedMessage(keyID, pub))
	_, err = s.db.Exec(`INSERT INTO keys(key_id, project, day, gen, pub, sig, wrapped, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		keyID, project, day, gen, pub, sig, wrapped, now())
	if err != nil {
		return nil, err
	}
	events.Emit("keysvc", "key_created", map[string]any{"key_id": keyID, "wrapper": s.wrapper.Name()})
	return &keyRow{KeyID: keyID, Project: project, Day: day, Gen: gen, Pub: pub, Sig: sig}, nil
}

func (s *server) unwrap(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	c, _, err := auth.FromRequest(r)
	if err != nil {
		s.audit(&auth.Claims{}, req.KeyID, "unwrap", false, "invalid token")
		httpErr(w, 401, "invalid token")
		return
	}
	k, err := s.byID(req.KeyID)
	if err != nil || k == nil {
		s.audit(c, req.KeyID, "unwrap", false, "unknown key")
		httpErr(w, 404, "unknown key")
		return
	}
	reason := ""
	switch {
	case c.Role != auth.RoleMember:
		reason = fmt.Sprintf("role %q has no decrypt path", c.Role)
	case c.Project != k.Project:
		reason = fmt.Sprintf("token project %q is not key project %q", c.Project, k.Project)
	}
	if reason != "" {
		s.audit(c, k.KeyID, "unwrap", false, reason)
		httpErr(w, 403, reason)
		return
	}
	if k.Destroyed.Valid {
		reason = "key destroyed (" + k.Reason.String + ")"
		s.audit(c, k.KeyID, "unwrap", false, reason)
		httpErr(w, 410, reason)
		return
	}
	priv, err := s.wrapper.Unwrap(r.Context(), k.Project, k.Wrapped.String)
	if err != nil {
		s.audit(c, k.KeyID, "unwrap", false, "wrapper: "+err.Error())
		httpErr(w, 502, "unwrap failed")
		return
	}
	s.audit(c, k.KeyID, "unwrap", true, "project member")
	writeJSON(w, 200, map[string]any{"key_id": k.KeyID, "priv": priv})
	clear(priv)
}

// purge destroys every key for a project over a day range. The ciphertext stays
// where it is and becomes unreadable.
func (s *server) purge(w http.ResponseWriter, r *http.Request) {
	var req struct{ Project, From, To string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	c, _, err := auth.FromRequest(r)
	if err != nil || c.Role != auth.RoleMember || c.Project != req.Project {
		httpErr(w, 403, "project member token required")
		return
	}
	ids := s.destroy("purge", `project=? AND day BETWEEN ? AND ?`, req.Project, req.From, req.To)
	s.audit(c, fmt.Sprintf("%s/%s..%s", req.Project, req.From, req.To), "purge", true, fmt.Sprintf("%d keys", len(ids)))
	writeJSON(w, 200, map[string]any{"destroyed": ids})
}

func (s *server) destroy(reason, where string, args ...any) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT key_id FROM keys WHERE destroyed_at IS NULL AND `+where, args...)
	if err != nil {
		return nil
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_, _ = s.db.Exec(`UPDATE keys SET wrapped=NULL, destroyed_at=?, destroy_reason=? WHERE key_id=?`, now(), reason, id)
		_, _ = s.db.Exec(`INSERT INTO revocations(key_id, ts) VALUES(?, ?)`, id, now())
	}
	if len(ids) > 0 {
		events.Emit("keysvc", "keys_destroyed", map[string]any{"reason": reason, "key_ids": ids})
	}
	return ids
}

func (s *server) retentionLoop() {
	for {
		cutoff := time.Now().UTC().AddDate(0, 0, -s.retention).Format(dayFmt)
		s.destroy("retention", `day < ?`, cutoff)
		time.Sleep(30 * time.Second)
	}
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	if _, _, err := auth.FromRequest(r); err != nil {
		httpErr(w, 401, "invalid token")
		return
	}
	rows, err := s.db.Query(`SELECT key_id, day, gen, created_at, destroyed_at, destroy_reason, pub, wrapped FROM keys WHERE project=? ORDER BY day, gen`, project)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, day, created string
		var gen int
		var destroyed, reason, wrapped sql.NullString
		var pub []byte
		if rows.Scan(&id, &day, &gen, &created, &destroyed, &reason, &pub, &wrapped) == nil {
			status := "live"
			if destroyed.Valid {
				status = "destroyed: " + reason.String
			}
			// Public key and the OpenBao-wrapped private key are safe to show; the
			// plaintext private key never leaves /unwrap.
			w := wrapped.String
			if len(w) > 48 {
				w = w[:48] + "…"
			}
			out = append(out, map[string]any{"key_id": id, "day": day, "gen": gen, "status": status, "created_at": created,
				"destroyed_at": destroyed.String, "pub_hex": events.Preview(pub, 32), "wrapped": w, "wrapper": s.wrapper.Name()})
		}
	}
	writeJSON(w, 200, out)
}

// revocations is the feed decrypters poll to evict cached keys. Purge latency is
// bounded by their poll interval, not by their cache TTL.
func (s *server) revocations(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	rows, err := s.db.Query(`SELECT seq, key_id FROM revocations WHERE seq > ? ORDER BY seq`, after)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type rev struct {
		Seq   int    `json:"seq"`
		KeyID string `json:"key_id"`
	}
	out := []rev{}
	for rows.Next() {
		var x rev
		if rows.Scan(&x.Seq, &x.KeyID) == nil {
			out = append(out, x)
		}
	}
	writeJSON(w, 200, out)
}

// auditLog is the observer view of the audit table, newest first. Demo only: a real
// deployment would ship audit records to an append-only store.
func (s *server) auditLog(w http.ResponseWriter, r *http.Request) {
	if _, _, err := auth.FromRequest(r); err != nil {
		httpErr(w, 401, "invalid token")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT ts, sub, caller_project, role, key_id, action, allowed, reason FROM audit
		WHERE key_id = ? OR ? = '' ORDER BY id DESC LIMIT ?`, r.URL.Query().Get("key_id"), r.URL.Query().Get("key_id"), limit)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ts, sub, proj, role, key, action, reason string
		var allowed bool
		if rows.Scan(&ts, &sub, &proj, &role, &key, &action, &allowed, &reason) == nil {
			out = append(out, map[string]any{"ts": ts, "sub": sub, "caller_project": proj, "role": role,
				"key_id": key, "action": action, "allowed": allowed, "reason": reason})
		}
	}
	writeJSON(w, 200, out)
}

func (s *server) audit(c *auth.Claims, keyID, action string, allowed bool, reason string) {
	_, _ = s.db.Exec(`INSERT INTO audit(ts, sub, caller_project, role, key_id, action, allowed, reason) VALUES(?,?,?,?,?,?,?,?)`,
		now(), c.Subject, c.Project, c.Role, keyID, action, allowed, reason)
	events.Emit("keysvc", action, map[string]any{
		"key_id": keyID, "sub": c.Subject, "role": c.Role, "caller_project": c.Project, "allowed": allowed, "reason": reason,
	})
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

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
