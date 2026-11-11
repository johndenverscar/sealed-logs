// keysvc issues one key pair per project per day, wraps private keys with the
// master-key backend, and unwraps only for members of the key's own project, or
// for operator staff holding a time-boxed access grant that a member approved.
// Every unwrap, denial, grant, purge and expiry is audited.
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
	"strings"
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
	tr := wrap.NewTransit(config.BaoAddr, config.BaoToken)
	must(tr.Init(ctx))
	retention, _ := strconv.Atoi(config.Env("RETENTION_DAYS", "7"))
	s, err := newServer(db, tr, loadSigningKey(), os.Getenv("DEMO_ALLOW_PAST") == "1", retention)
	must(err)

	go s.retentionLoop()

	addr := config.Env("KEYSVC_ADDR", "127.0.0.1:7101")
	log.Printf("keysvc on %s, wrapper=%s, retention=%dd", addr, tr.Name(), retention)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}

const schema = `
CREATE TABLE IF NOT EXISTS keys(
  key_id TEXT PRIMARY KEY, project TEXT, day TEXT, gen INTEGER,
  pub BLOB, sig BLOB, wrapped TEXT, created_at TEXT, destroyed_at TEXT, destroy_reason TEXT);
CREATE TABLE IF NOT EXISTS revocations(seq INTEGER PRIMARY KEY AUTOINCREMENT, key_id TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS grants(
  id TEXT PRIMARY KEY, project TEXT, grantee TEXT, reason TEXT, minutes INTEGER, status TEXT,
  requested_at TEXT, decided_by TEXT, decided_at TEXT, expires_at TEXT, ended_by TEXT, ended_at TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, sub TEXT, caller_project TEXT, role TEXT,
  key_id TEXT, action TEXT, allowed INTEGER, reason TEXT);`

func newServer(db *sql.DB, w wrap.KeyWrapper, sign ed25519.PrivateKey, allowPast bool, retention int) (*server, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	// A revocation either destroys a key (key_id) or ends someone's access (sub).
	// Older databases predate the sub column.
	_, _ = db.Exec(`ALTER TABLE revocations ADD COLUMN sub TEXT`)
	return &server{db: db, wrapper: w, sign: sign, allowPast: allowPast, retention: retention}, nil
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /signing-key", s.signingKey)
	mux.HandleFunc("GET /pubkey", s.pubkey)
	mux.HandleFunc("POST /unwrap", s.unwrap)
	mux.HandleFunc("POST /purge", s.purge)
	mux.HandleFunc("GET /keys", s.list)
	mux.HandleFunc("GET /revocations", s.revocations)
	mux.HandleFunc("GET /audit", s.auditLog)
	mux.HandleFunc("POST /grants", s.requestGrant)
	mux.HandleFunc("GET /grants", s.listGrants)
	mux.HandleFunc("POST /grants/{id}/{action}", s.decideGrant)
	return mux
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
	reason, allowReason := "", "project member"
	var expires time.Time
	switch {
	case c.Role == auth.RoleStaff:
		// Staff never decrypt on their own authority. A member of the project has to
		// approve a grant, and it only lasts as long as they agreed to.
		g := s.activeGrant(c.Subject, k.Project)
		if g == nil {
			reason = fmt.Sprintf("role %q has no decrypt path: no active access grant for %s", c.Role, k.Project)
			break
		}
		expires = g.Expires
		allowReason = fmt.Sprintf("support access grant %s, approved by %s, until %s", g.ID, g.DecidedBy, g.Expires.Format("15:04:05Z"))
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
	s.audit(c, k.KeyID, "unwrap", true, allowReason)
	out := map[string]any{"key_id": k.KeyID, "priv": priv}
	if !expires.IsZero() {
		out["expires_at"] = expires // decrypters must not cache the key past this
	}
	writeJSON(w, 200, out)
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
		s.expireGrants()
		time.Sleep(5 * time.Second)
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

// revocations is the feed decrypters poll to evict cached decisions: a destroyed
// key (key_id), or a person whose access grant started or ended (sub). Purge latency is
// bounded by their poll interval, not by their cache TTL.
func (s *server) revocations(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	rows, err := s.db.Query(`SELECT seq, COALESCE(key_id, ''), COALESCE(sub, '') FROM revocations WHERE seq > ? ORDER BY seq`, after)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type rev struct {
		Seq   int    `json:"seq"`
		KeyID string `json:"key_id,omitempty"`
		Sub   string `json:"sub,omitempty"`
	}
	out := []rev{}
	for rows.Next() {
		var x rev
		if rows.Scan(&x.Seq, &x.KeyID, &x.Sub) == nil {
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

// ---- just-in-time support access ----

const maxGrantMinutes = 60

type grant struct {
	ID        string    `json:"id"`
	Project   string    `json:"project"`
	Grantee   string    `json:"grantee"`
	Reason    string    `json:"reason"`
	Minutes   int       `json:"minutes"`
	Status    string    `json:"status"` // pending, active, denied, revoked, expired
	Requested time.Time `json:"requested_at"`
	DecidedBy string    `json:"decided_by,omitempty"`
	Expires   time.Time `json:"expires_at,omitzero"`
	EndedBy   string    `json:"ended_by,omitempty"`
}

const grantCols = `id, project, grantee, reason, minutes, status, requested_at,
	COALESCE(decided_by, ''), COALESCE(expires_at, ''), COALESCE(ended_by, '')`

func scanGrant(sc interface{ Scan(...any) error }) (*grant, error) {
	g := &grant{}
	var req, exp string
	if err := sc.Scan(&g.ID, &g.Project, &g.Grantee, &g.Reason, &g.Minutes, &g.Status, &req, &g.DecidedBy, &exp, &g.EndedBy); err != nil {
		return nil, err
	}
	g.Requested, _ = time.Parse(time.RFC3339Nano, req)
	g.Expires, _ = time.Parse(time.RFC3339Nano, exp)
	if g.Status == "active" && !time.Now().Before(g.Expires) {
		g.Status = "expired"
	}
	return g, nil
}

func (s *server) grantByID(id string) *grant {
	g, err := scanGrant(s.db.QueryRow(`SELECT `+grantCols+` FROM grants WHERE id=?`, id))
	if err != nil {
		return nil
	}
	return g
}

// activeGrant is the grant that lets this staff member decrypt a project's
// keys right now, if there is one.
func (s *server) activeGrant(sub, project string) *grant {
	rows, err := s.db.Query(`SELECT `+grantCols+` FROM grants WHERE grantee=? AND project=? AND status='active'`, sub, project)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		if g, err := scanGrant(rows); err == nil && g.Status == "active" {
			return g
		}
	}
	return nil
}

// requestGrant is a staff member asking a project for temporary read access.
// Nothing changes until a member of that project approves it.
func (s *server) requestGrant(w http.ResponseWriter, r *http.Request) {
	c, _, err := auth.FromRequest(r)
	if err != nil || c.Role != auth.RoleStaff {
		httpErr(w, 403, "only operator staff request access")
		return
	}
	var req struct {
		Project string `json:"project"`
		Reason  string `json:"reason"`
		Minutes int    `json:"minutes"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Project == "" || strings.TrimSpace(req.Reason) == "" {
		httpErr(w, 400, "project and reason are required")
		return
	}
	if req.Minutes < 1 || req.Minutes > maxGrantMinutes {
		httpErr(w, 400, fmt.Sprintf("minutes must be 1 to %d", maxGrantMinutes))
		return
	}
	if s.activeGrant(c.Subject, req.Project) != nil {
		httpErr(w, 409, "you already have access to this project")
		return
	}
	id := "gr_" + randID()
	_, err = s.db.Exec(`INSERT INTO grants(id, project, grantee, reason, minutes, status, requested_at) VALUES(?,?,?,?,?,'pending',?)`,
		id, req.Project, c.Subject, req.Reason, req.Minutes, now())
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	s.audit(c, req.Project, "grant_request", true, fmt.Sprintf("%s: %d min, %q", id, req.Minutes, req.Reason))
	writeJSON(w, 201, s.grantByID(id))
}

// listGrants shows a project's members every grant for their project, and staff
// their own.
func (s *server) listGrants(w http.ResponseWriter, r *http.Request) {
	c, _, err := auth.FromRequest(r)
	if err != nil {
		httpErr(w, 401, "invalid token")
		return
	}
	project := r.URL.Query().Get("project")
	var rows *sql.Rows
	switch {
	case c.Role == auth.RoleMember && c.Project == project:
		rows, err = s.db.Query(`SELECT `+grantCols+` FROM grants WHERE project=? ORDER BY requested_at DESC LIMIT 20`, project)
	case c.Role == auth.RoleStaff:
		rows, err = s.db.Query(`SELECT `+grantCols+` FROM grants WHERE grantee=? AND (project=? OR ?='') ORDER BY requested_at DESC LIMIT 20`, c.Subject, project, project)
	default:
		httpErr(w, 403, "members of the project, or the staff member asking, only")
		return
	}
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []*grant{}
	for rows.Next() {
		if g, err := scanGrant(rows); err == nil {
			out = append(out, g)
		}
	}
	writeJSON(w, 200, out)
}

// decideGrant approves, denies or ends a grant. Members of the grant's project
// decide; the staff member can also end their own access early.
func (s *server) decideGrant(w http.ResponseWriter, r *http.Request) {
	c, _, err := auth.FromRequest(r)
	if err != nil {
		httpErr(w, 401, "invalid token")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grantByID(r.PathValue("id"))
	if g == nil {
		httpErr(w, 404, "unknown grant")
		return
	}
	member := c.Role == auth.RoleMember && c.Project == g.Project
	action := r.PathValue("action")
	var res sql.Result
	switch {
	case action == "approve" && member && g.Status == "pending":
		exp := time.Now().UTC().Add(time.Duration(g.Minutes) * time.Minute)
		res, err = s.db.Exec(`UPDATE grants SET status='active', decided_by=?, decided_at=?, expires_at=? WHERE id=? AND status='pending'`,
			c.Subject, now(), exp.Format(time.RFC3339Nano), g.ID)
	case action == "deny" && member && g.Status == "pending":
		res, err = s.db.Exec(`UPDATE grants SET status='denied', decided_by=?, decided_at=? WHERE id=? AND status='pending'`, c.Subject, now(), g.ID)
	case action == "revoke" && (member || c.Subject == g.Grantee) && g.Status == "active":
		res, err = s.db.Exec(`UPDATE grants SET status='revoked', ended_by=?, ended_at=? WHERE id=? AND status='active'`, c.Subject, now(), g.ID)
	default:
		reason := fmt.Sprintf("%s %s grant: not allowed for %s (%s)", action, g.Status, c.Subject, c.Role)
		s.audit(c, g.Project, "grant_"+action, false, g.ID+": "+reason)
		httpErr(w, 403, reason)
		return
	}
	if err == nil {
		if n, _ := res.RowsAffected(); n != 1 {
			err = errors.New("grant changed underneath us")
		}
	}
	if err == nil && action != "deny" {
		// This person's access changed: decrypters drop every decision they cached
		// for them (keys after a revoke, denials after an approval).
		_, err = s.db.Exec(`INSERT INTO revocations(sub, ts) VALUES(?, ?)`, g.Grantee, now())
	}
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	s.audit(c, g.Project, "grant_"+action, true, fmt.Sprintf("%s for %s", g.ID, g.Grantee))
	writeJSON(w, 200, s.grantByID(g.ID))
}

// expireGrants records grants that ran out. Unwrap already refuses them; this
// keeps the audit log and the grant list honest.
func (s *server) expireGrants() {
	rows, err := s.db.Query(`SELECT id, project, grantee FROM grants WHERE status='active' AND expires_at <= ?`, now())
	if err != nil {
		return
	}
	type ended struct{ id, project, grantee string }
	var done []ended
	for rows.Next() {
		var e ended
		if rows.Scan(&e.id, &e.project, &e.grantee) == nil {
			done = append(done, e)
		}
	}
	rows.Close()
	for _, e := range done {
		_, _ = s.db.Exec(`UPDATE grants SET status='expired', ended_at=? WHERE id=?`, now(), e.id)
		_, _ = s.db.Exec(`INSERT INTO revocations(sub, ts) VALUES(?, ?)`, e.grantee, now())
		s.audit(&auth.Claims{Role: "system"}, e.project, "grant_expire", true, e.id+" for "+e.grantee)
	}
}

func randID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
