package envelope

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func fixture(t *testing.T) (pub, priv []byte, m Meta, lines []Line) {
	t.Helper()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	m = Meta{
		Project: "p_demo", ChunkID: "c_1", KeyID: "p_demo/2026-01-02/g1", SessionID: "ses_1",
		AgentID: "ag_1", Source: "sidecar", TSMin: ts, TSMax: ts.Add(time.Second), Lines: 2,
		Levels: map[string]uint32{"info": 1, "error": 1},
	}
	lines = []Line{
		{TS: ts, Level: "info", Msg: "hello"},
		{TS: ts.Add(time.Second), Level: "error", Msg: "card 4111 1111 1111 1111", Attrs: map[string]string{"k": "v"}},
	}
	return pub, priv, m, lines
}

func TestRoundTrip(t *testing.T) {
	pub, priv, m, lines := fixture(t)
	s, n, err := Seal(pub, m, lines)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || len(s.Enc) != 32 {
		t.Fatalf("plaintext bytes %d, enc %d", n, len(s.Enc))
	}
	got, err := Open(priv, m, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Msg != lines[1].Msg || got[1].Attrs["k"] != "v" {
		t.Fatalf("got %+v", got)
	}
}

// The ciphertext must not contain the message, even compressed.
func TestCiphertextHidesText(t *testing.T) {
	pub, _, m, lines := fixture(t)
	s, _, _ := Seal(pub, m, lines)
	body, _ := json.Marshal(Chunk{Meta: m, Sealed: s})
	for _, needle := range []string{"4111", "hello", "card"} {
		if bytes.Contains(body, []byte(needle)) {
			t.Errorf("stored chunk contains %q", needle)
		}
	}
}

// Metadata is plaintext so storage can index it, but it is authenticated:
// changing any field makes Open fail.
func TestMetadataIsBound(t *testing.T) {
	pub, priv, m, lines := fixture(t)
	s, _, _ := Seal(pub, m, lines)
	tamper := map[string]func(*Meta){
		"project":    func(m *Meta) { m.Project = "p_other" },
		"chunk_id":   func(m *Meta) { m.ChunkID = "c_2" },
		"key_id":     func(m *Meta) { m.KeyID = "p_demo/2026-01-03/g1" },
		"session_id": func(m *Meta) { m.SessionID = "ses_2" },
		"agent_id":   func(m *Meta) { m.AgentID = "ag_2" },
		"source":     func(m *Meta) { m.Source = "sdk" },
		"ts_min":     func(m *Meta) { m.TSMin = m.TSMin.Add(-time.Hour) },
		"ts_max":     func(m *Meta) { m.TSMax = m.TSMax.Add(time.Hour) },
		"lines":      func(m *Meta) { m.Lines = 1 },
		"levels":     func(m *Meta) { m.Levels = map[string]uint32{"info": 2} },
	}
	for name, f := range tamper {
		mm := m
		mm.Levels = map[string]uint32{"info": 1, "error": 1}
		f(&mm)
		if _, err := Open(priv, mm, s); err == nil {
			t.Errorf("tampered %s still opens", name)
		}
	}
	// Same values in another time zone and a JSON round trip still open.
	b, _ := json.Marshal(m)
	var rt Meta
	_ = json.Unmarshal(b, &rt)
	rt.TSMin = rt.TSMin.In(time.FixedZone("x", 3600))
	if _, err := Open(priv, rt, s); err != nil {
		t.Errorf("round-tripped meta: %v", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	pub, priv, m, lines := fixture(t)
	s, _, _ := Seal(pub, m, lines)
	s.CT[len(s.CT)/2] ^= 1
	if _, err := Open(priv, m, s); err == nil {
		t.Fatal("flipped ciphertext bit still opens")
	}
}

func TestWrongKey(t *testing.T) {
	pub, _, m, lines := fixture(t)
	_, other, _ := GenerateKeyPair()
	s, _, _ := Seal(pub, m, lines)
	if _, err := Open(other, m, s); err == nil {
		t.Fatal("another key opens the chunk")
	}
}

// Each seal uses a fresh ephemeral key, so equal input never gives equal output.
func TestSealIsRandomised(t *testing.T) {
	pub, _, m, lines := fixture(t)
	a, _, _ := Seal(pub, m, lines)
	b, _, _ := Seal(pub, m, lines)
	if bytes.Equal(a.Enc, b.Enc) || bytes.Equal(a.CT, b.CT) {
		t.Fatal("two seals of the same input are identical")
	}
}

func TestUnknownVersion(t *testing.T) {
	pub, priv, m, lines := fixture(t)
	s, _, _ := Seal(pub, m, lines)
	s.V = 2
	if _, err := Open(priv, m, s); err == nil {
		t.Fatal("unknown version opens")
	}
}
