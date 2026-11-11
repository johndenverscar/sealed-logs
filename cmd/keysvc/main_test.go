package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/envelope"
	"sealedlogs/internal/wrap"
)

// fakeWrapper stands in for OpenBao. Like Transit with a derived key, a blob
// wrapped for one project does not unwrap for another.
type fakeWrapper struct{}

func (fakeWrapper) Name() string { return "fake" }
func (fakeWrapper) Wrap(_ context.Context, project string, key []byte) (string, error) {
	return project + ":" + base64.StdEncoding.EncodeToString(key), nil
}
func (fakeWrapper) Unwrap(_ context.Context, project, blob string) ([]byte, error) {
	p, b, ok := strings.Cut(blob, ":")
	if !ok || p != project {
		return nil, errors.New("wrong derivation context")
	}
	return base64.StdEncoding.DecodeString(b)
}

func newTest(t *testing.T) (*server, *httptest.Server) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1) // one connection, so every query sees the same in-memory database
	_, sk, _ := ed25519.GenerateKey(nil)
	s, err := newServer(db, fakeWrapper{}, sk, true, 7)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return s, ts
}

func call(t *testing.T, ts *httptest.Server, method, path, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, ts.URL+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// unsigned builds a JWT with "alg":"none" and no signature, the classic forgery.
func unsigned(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(claims)) + "."
}

func today() string { return time.Now().UTC().Format(dayFmt) }

// issue asks for today's public key as p_demo's producer and checks the signature.
func issue(t *testing.T, s *server, ts *httptest.Server) (keyID string, pub []byte) {
	t.Helper()
	code, out := call(t, ts, "GET", "/pubkey?project=p_demo", auth.Mint("w", "p_demo", auth.RoleProducer, time.Hour), nil)
	if code != 200 {
		t.Fatalf("pubkey: %d %v", code, out)
	}
	keyID = out["key_id"].(string)
	pub, _ = base64.StdEncoding.DecodeString(out["pub"].(string))
	sig, _ := base64.StdEncoding.DecodeString(out["sig"].(string))
	if !ed25519.Verify(s.sign.Public().(ed25519.PublicKey), envelope.SignedMessage(keyID, pub), sig) {
		t.Fatal("public key signature does not verify")
	}
	return keyID, pub
}

func TestPubkeyRequiresOwnProducer(t *testing.T) {
	_, ts := newTest(t)
	for name, tok := range map[string]string{
		"member":         auth.Mint("u", "p_demo", auth.RoleMember, time.Hour),
		"staff":          auth.Mint("s", "", auth.RoleStaff, time.Hour),
		"other producer": auth.Mint("w", "p_other", auth.RoleProducer, time.Hour),
		"no token":       "",
	} {
		if code, _ := call(t, ts, "GET", "/pubkey?project=p_demo", tok, nil); code != 403 {
			t.Errorf("%s got %d, want 403", name, code)
		}
	}
}

// The unwrap policy is the core of the design: only a member of the key's own
// project gets the private key. Every decision is audited.
func TestUnwrapPolicy(t *testing.T) {
	s, ts := newTest(t)
	keyID, pub := issue(t, s, ts)

	cases := []struct {
		name string
		tok  string
		want int
	}{
		{"project admin", auth.MintMember("u_alice", "p_demo", auth.ProjectAdmin, time.Hour), 200},
		{"project viewer", auth.MintMember("u_carol", "p_demo", auth.ProjectViewer, time.Hour), 200},
		{"staff", auth.Mint("s_bob", "", auth.RoleStaff, time.Hour), 403},
		{"staff claiming the project", auth.Mint("s_bob", "p_demo", auth.RoleStaff, time.Hour), 403},
		{"other project's member", auth.Mint("u_mallory", "p_other", auth.RoleMember, time.Hour), 403},
		{"producer", auth.Mint("w", "p_demo", auth.RoleProducer, time.Hour), 403},
		{"expired member", auth.Mint("u_alice", "p_demo", auth.RoleMember, -time.Minute), 401},
		{"unsigned token (alg none)", unsigned(`{"project":"p_demo","role":"member"}`), 401},
	}
	for _, c := range cases {
		code, out := call(t, ts, "POST", "/unwrap", c.tok, map[string]string{"key_id": keyID})
		if code != c.want {
			t.Errorf("%s: got %d %v, want %d", c.name, code, out, c.want)
			continue
		}
		if code == 200 {
			priv, _ := base64.StdEncoding.DecodeString(out["priv"].(string))
			m := envelope.Meta{Project: "p_demo", ChunkID: "c", KeyID: keyID}
			sl, _, _ := envelope.Seal(pub, m, []envelope.Line{{Msg: "x"}})
			if _, err := envelope.Open(priv, m, sl); err != nil {
				t.Errorf("unwrapped key does not open: %v", err)
			}
		} else if out["priv"] != nil {
			t.Errorf("%s: denied response carries a key", c.name)
		}
	}

	var allowed, denied int
	_ = s.db.QueryRow(`SELECT SUM(allowed), SUM(1-allowed) FROM audit WHERE action='unwrap'`).Scan(&allowed, &denied)
	if allowed != 2 || denied != len(cases)-2 {
		t.Errorf("audit rows: %d allowed, %d denied", allowed, denied)
	}
}

// Purge is crypto-shredding: the wrapped key is deleted, a revocation is
// published, unwrap answers 410, and the next pubkey is a new generation.
func TestPurge(t *testing.T) {
	s, ts := newTest(t)
	keyID, _ := issue(t, s, ts)
	member := auth.MintMember("u_alice", "p_demo", auth.ProjectAdmin, time.Hour)

	for name, tok := range map[string]string{
		"another project's admin": auth.MintMember("u_mallory", "p_other", auth.ProjectAdmin, time.Hour),
		"a viewer":                auth.MintMember("u_carol", "p_demo", auth.ProjectViewer, time.Hour),
	} {
		if code, _ := call(t, ts, "POST", "/purge", tok, map[string]string{"Project": "p_demo", "From": today(), "To": today()}); code != 403 {
			t.Fatalf("%s purged p_demo: %d", name, code)
		}
	}
	code, out := call(t, ts, "POST", "/purge", member, map[string]string{"Project": "p_demo", "From": today(), "To": today()})
	if code != 200 || len(out["destroyed"].([]any)) != 1 {
		t.Fatalf("purge: %d %v", code, out)
	}

	var wrapped sql.NullString
	_ = s.db.QueryRow(`SELECT wrapped FROM keys WHERE key_id=?`, keyID).Scan(&wrapped)
	if wrapped.Valid {
		t.Error("wrapped private key still stored after purge")
	}
	if code, _ := call(t, ts, "POST", "/unwrap", member, map[string]string{"key_id": keyID}); code != 410 {
		t.Errorf("unwrap after purge: %d, want 410", code)
	}

	resp, _ := http.Get(ts.URL + "/revocations?after=0")
	var revs []struct {
		KeyID string `json:"key_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&revs)
	resp.Body.Close()
	if len(revs) != 1 || revs[0].KeyID != keyID {
		t.Errorf("revocations: %+v", revs)
	}

	next, _ := issue(t, s, ts)
	if next == keyID || !strings.HasSuffix(next, "/g2") {
		t.Errorf("key after purge: %s", next)
	}
}

func TestRetention(t *testing.T) {
	s, ts := newTest(t)
	old := time.Now().UTC().AddDate(0, 0, -3).Format(dayFmt)
	code, out := call(t, ts, "GET", "/pubkey?project=p_demo&day="+old, auth.Mint("w", "p_demo", auth.RoleProducer, time.Hour), nil)
	if code != 200 {
		t.Fatalf("pubkey: %d %v", code, out)
	}
	s.retention = 2
	s.destroy("retention", `day < ?`, time.Now().UTC().AddDate(0, 0, -s.retention).Format(dayFmt))
	code, _ = call(t, ts, "POST", "/unwrap", auth.Mint("u_alice", "p_demo", auth.RoleMember, time.Hour), map[string]string{"key_id": out["key_id"].(string)})
	if code != 410 {
		t.Errorf("unwrap past retention: %d, want 410", code)
	}
}

// Support access is a grant a project member approves. Until then staff get
// nothing; while it lasts they can read that project only; when it ends, early
// or on time, they are back to nothing and decrypters are told.
func TestSupportGrant(t *testing.T) {
	s, ts := newTest(t)
	keyID, _ := issue(t, s, ts)
	staff := auth.Mint("s_bob", "", auth.RoleStaff, time.Hour)
	otherStaff := auth.Mint("s_eve", "", auth.RoleStaff, time.Hour)
	member := auth.MintMember("u_alice", "p_demo", auth.ProjectAdmin, time.Hour)
	viewer := auth.MintMember("u_carol", "p_demo", auth.ProjectViewer, time.Hour)
	outsider := auth.MintMember("u_mallory", "p_other", auth.ProjectAdmin, time.Hour)
	unwrap := func(tok string) (int, map[string]any) {
		return call(t, ts, "POST", "/unwrap", tok, map[string]string{"key_id": keyID})
	}

	if code, _ := call(t, ts, "POST", "/grants", member, map[string]any{"project": "p_demo", "reason": "x", "minutes": 5}); code != 403 {
		t.Errorf("a member requested staff access: %d", code)
	}
	if code, _ := call(t, ts, "POST", "/grants", staff, map[string]any{"project": "p_demo", "reason": "x", "minutes": 600}); code != 400 {
		t.Errorf("10-hour grant accepted: %d", code)
	}
	code, g := call(t, ts, "POST", "/grants", staff, map[string]any{"project": "p_demo", "reason": "ticket 4821", "minutes": 5})
	if code != 201 || g["status"] != "pending" {
		t.Fatalf("request: %d %v", code, g)
	}
	id := g["id"].(string)
	if code, _ := unwrap(staff); code != 403 {
		t.Errorf("pending grant let staff decrypt: %d", code)
	}
	for name, tok := range map[string]string{"the staff member": staff, "another project's admin": outsider, "other staff": otherStaff, "a viewer": viewer} {
		if code, _ := call(t, ts, "POST", "/grants/"+id+"/approve", tok, nil); code != 403 {
			t.Errorf("%s approved the grant: %d", name, code)
		}
	}

	if code, out := call(t, ts, "POST", "/grants/"+id+"/approve", member, nil); code != 200 || out["status"] != "active" {
		t.Fatalf("approve: %d %v", code, out)
	}
	code, out := unwrap(staff)
	if code != 200 || out["expires_at"] == nil {
		t.Fatalf("approved grant: %d %v", code, out)
	}
	if code, _ := unwrap(otherStaff); code != 403 {
		t.Errorf("a grant for s_bob let s_eve decrypt: %d", code)
	}

	// A grant for p_demo is no use on another project's keys.
	code, other := call(t, ts, "GET", "/pubkey?project=p_other", auth.Mint("w", "p_other", auth.RoleProducer, time.Hour), nil)
	if code != 200 {
		t.Fatal(code)
	}
	if code, _ := call(t, ts, "POST", "/unwrap", staff, map[string]string{"key_id": other["key_id"].(string)}); code != 403 {
		t.Errorf("p_demo grant opened a p_other key: %d", code)
	}

	if code, _ := call(t, ts, "POST", "/grants/"+id+"/revoke", member, nil); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := unwrap(staff); code != 403 {
		t.Errorf("revoked grant still decrypts: %d", code)
	}
	var subs int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM revocations WHERE sub='s_bob'`).Scan(&subs)
	if subs != 2 {
		t.Errorf("approve and revoke published %d access changes for s_bob, want 2", subs)
	}

	// Expiry: approve a new grant, then move its end into the past.
	_, g = call(t, ts, "POST", "/grants", staff, map[string]any{"project": "p_demo", "reason": "again", "minutes": 1})
	id = g["id"].(string)
	call(t, ts, "POST", "/grants/"+id+"/approve", member, nil)
	_, _ = s.db.Exec(`UPDATE grants SET expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), id)
	if code, _ := unwrap(staff); code != 403 {
		t.Errorf("expired grant still decrypts: %d", code)
	}
	s.expireGrants()
	var status string
	_ = s.db.QueryRow(`SELECT status FROM grants WHERE id=?`, id).Scan(&status)
	if status != "expired" {
		t.Errorf("grant status after expiry: %s", status)
	}
}

// The access log is the project's view of the audit. It is hash-chained, so
// editing or deleting a row is visible to whoever checks the chain.
func TestAccessLog(t *testing.T) {
	s, ts := newTest(t)
	keyID, _ := issue(t, s, ts)
	admin := auth.MintMember("u_alice", "p_demo", auth.ProjectAdmin, time.Hour)
	call(t, ts, "POST", "/unwrap", admin, map[string]string{"key_id": keyID})
	call(t, ts, "POST", "/unwrap", auth.Mint("s_bob", "", auth.RoleStaff, time.Hour), map[string]string{"key_id": keyID})
	call(t, ts, "POST", "/grants", auth.Mint("s_bob", "", auth.RoleStaff, time.Hour), map[string]any{"project": "p_demo", "reason": "x", "minutes": 5})
	call(t, ts, "POST", "/unwrap", auth.MintMember("u_mallory", "p_other", auth.ProjectAdmin, time.Hour), map[string]string{"key_id": keyID})

	for name, tok := range map[string]string{
		"a viewer":                auth.MintMember("u_carol", "p_demo", auth.ProjectViewer, time.Hour),
		"staff":                   auth.Mint("s_bob", "", auth.RoleStaff, time.Hour),
		"another project's admin": auth.MintMember("u_mallory", "p_other", auth.ProjectAdmin, time.Hour),
	} {
		if code, _ := call(t, ts, "GET", "/access-log?project=p_demo", tok, nil); code != 403 {
			t.Errorf("%s read p_demo's access log: %d", name, code)
		}
	}
	code, out := call(t, ts, "GET", "/access-log?project=p_demo", admin, nil)
	chain, _ := out["chain"].(map[string]any)
	if code != 200 || chain["intact"] != true || chain["entries"].(float64) != 4 {
		t.Fatalf("access log: %d %v", code, out)
	}

	// Quietly soften one row, the way someone covering their tracks would.
	_, _ = s.db.Exec(`UPDATE audit SET reason='project member' WHERE sub='s_bob' AND action='unwrap'`)
	_, out = call(t, ts, "GET", "/access-log?project=p_demo", admin, nil)
	chain, _ = out["chain"].(map[string]any)
	if chain["intact"] != false {
		t.Errorf("an edited row went unnoticed: %v", chain)
	}
}

// fakeCustomerKMS stands in for the customer's own KMS. Revoking takes decrypt
// away from the operator but leaves encrypt, the way a customer would restrict
// a KMS grant.
type fakeCustomerKMS struct{ revoked bool }

func (f *fakeCustomerKMS) wrapper(_, _, key string) wrap.KeyWrapper { return customerWrapper{f, key} }

type customerWrapper struct {
	f   *fakeCustomerKMS
	key string
}

func (customerWrapper) Name() string { return "fake-customer" }
func (w customerWrapper) Wrap(_ context.Context, _ string, b []byte) (string, error) {
	return w.key + ":" + base64.StdEncoding.EncodeToString(b), nil
}
func (w customerWrapper) Unwrap(_ context.Context, _ string, blob string) ([]byte, error) {
	if w.f.revoked {
		return nil, errors.New("permission denied")
	}
	k, b, ok := strings.Cut(blob, ":")
	if !ok || k != w.key {
		return nil, errors.New("not wrapped with this key")
	}
	return base64.StdEncoding.DecodeString(b)
}

// With BYOK, every day key, existing and new, is also wrapped with the
// customer's key. When the customer revokes, nobody can unwrap, logs still come
// in, and decrypters are told to drop what they cached.
func TestBYOK(t *testing.T) {
	s, ts := newTest(t)
	kms := &fakeCustomerKMS{}
	s.customerKey = kms.wrapper
	before, _ := issue(t, s, ts)
	admin := auth.MintMember("u_alice", "p_demo", auth.ProjectAdmin, time.Hour)
	cfg := map[string]string{"kms_addr": "kms.customer.example", "key_name": "p_demo-logs", "token": "t"}

	if code, _ := call(t, ts, "PUT", "/projects/p_demo/byok", auth.MintMember("u_carol", "p_demo", auth.ProjectViewer, time.Hour), cfg); code != 403 {
		t.Fatalf("a viewer changed the project's keys: %d", code)
	}
	code, out := call(t, ts, "PUT", "/projects/p_demo/byok", admin, cfg)
	if code != 200 || out["live_keys"].(float64) != 1 {
		t.Fatalf("enable: %d %v", code, out)
	}
	var by string
	_ = s.db.QueryRow(`SELECT wrapped_by FROM keys WHERE key_id=?`, before).Scan(&by)
	if by != "customer:p_demo-logs" {
		t.Errorf("existing key not rewrapped: %q", by)
	}
	if code, _ := call(t, ts, "POST", "/unwrap", admin, map[string]string{"key_id": before}); code != 200 {
		t.Fatalf("unwrap through the customer's key: %d", code)
	}

	kms.revoked = true
	if code, _ := call(t, ts, "POST", "/unwrap", admin, map[string]string{"key_id": before}); code != 423 {
		t.Errorf("unwrap after the customer revoked: %d, want 423", code)
	}
	// New keys can still be issued: the customer took decrypt away, not encrypt.
	s.db.Exec(`UPDATE keys SET destroyed_at=? WHERE key_id=?`, now(), before)
	if code, out := call(t, ts, "GET", "/pubkey?project=p_demo", auth.Mint("w", "p_demo", auth.RoleProducer, time.Hour), nil); code != 200 {
		t.Errorf("producers locked out while decrypt is revoked: %d %v", code, out)
	}
	s.checkCustomerKeys(context.Background())
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM revocations WHERE project='p_demo'`).Scan(&n)
	if n != 1 {
		t.Errorf("revocation not published when the key went away: %d", n)
	}
	kms.revoked = false
	s.checkCustomerKeys(context.Background())
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM revocations WHERE project='p_demo'`).Scan(&n)
	if n != 2 {
		t.Errorf("revocation not published when the key came back: %d", n)
	}
}
