package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLifecycle drives the demo against the kind cluster (./up.sh first): send a
// line, read it as three callers, scan storage, try plaintext, and inspect every
// stage.
func TestLifecycle(t *testing.T) {
	if os.Getenv("SEALED_LIVE") == "" {
		t.Skip("set SEALED_LIVE=1 with the cluster running")
	}
	d := newDemo()
	time.Sleep(2 * time.Second) // let kubectl logs attach before sending
	res := d.Send(Compose{Level: "error", Stream: "stderr", Session: "ses_test",
		Attrs: "order_id=88231 tool=charge_card", Msg: "charge failed for card 4111 1111 1111 1111 cvv 123"})
	tr := d.trace(res.Trace)
	if tr == nil {
		t.Fatalf("send failed: %s", res.Status)
	}
	waitFor(t, "the index row", func() bool { return len(d.Derive(tr).byStage["collector"]) >= 3 })

	for _, as := range []string{"member", "staff", "other"} {
		r := readIndexed(d, tr, as)
		t.Logf("%-6s → %s", as, r.Status)
		switch {
		case r.Read == nil:
			t.Errorf("%s: no read result: %s", as, r.Status)
		case as == "member" && len(r.Read.Lines) == 0:
			t.Errorf("member could not read the line: %s", r.Status)
		case as != "member" && len(r.Read.Lines) > 0:
			t.Errorf("%s read plaintext: %q", as, r.Read.Lines)
		}
	}
	waitFor(t, "aggregator events", func() bool { return len(d.Derive(tr).byStage["aggregator"]) >= 9 })
	scanned := d.Scan(tr)
	t.Logf("scan → %s", scanned.Status)
	if scanned.Zone != zSealed {
		t.Errorf("raw storage scan: %s", scanned.Status)
	}
	plain := SendPlaintext()
	t.Logf("old SDK → %s", plain.Status)
	if !strings.Contains(plain.Status, "collector 422 ") {
		t.Errorf("collector accepted plaintext: %s", plain.Status)
	}

	for _, st := range stages {
		t.Logf("---- %s ----", st)
		for _, l := range d.Inspect(tr, st) {
			t.Logf("  [%s] %s", l.Kind, l.Text)
		}
	}
	for i, s := range d.Derive(tr).Steps {
		t.Logf("%02d %-7s %-10s %s", i+1, s.Zone, s.Stage, s.Title)
	}
}

// TestLogsView checks the Logs view's backend: a member gets the line, and staff
// get the chunk's index metadata with no text.
func TestLogsView(t *testing.T) {
	if os.Getenv("SEALED_LIVE") == "" {
		t.Skip("set SEALED_LIVE=1 with the cluster running")
	}
	d := newDemo()
	time.Sleep(2 * time.Second)
	res := d.Send(Compose{Level: "warn", Stream: "stdout", Session: "ses_view", Msg: "logs view check 4111 1111 1111 1111"})
	tr := d.trace(res.Trace)
	if tr == nil {
		t.Fatalf("send failed: %s", res.Status)
	}
	waitFor(t, "the index row", func() bool { return len(d.Derive(tr).byStage["collector"]) >= 3 })
	chunkID := d.Derive(tr).ChunkID
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	type chunk struct {
		ChunkID string            `json:"chunk_id"`
		Status  string            `json:"status"`
		Session string            `json:"session_id"`
		Lines   int               `json:"lines"`
		Levels  map[string]uint32 `json:"levels"`
	}
	get := func(as string) (body string, chunks []chunk) {
		for i := 0; i < 20; i++ {
			resp, err := http.Get(srv.URL + "/api/logs?" + url.Values{"as": {as}, "since": {"1h"}, "session": {"ses_view"}}.Encode())
			if err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage
			_ = json.NewDecoder(resp.Body).Decode(&raw)
			resp.Body.Close()
			var out struct{ Chunks []chunk }
			_ = json.Unmarshal(raw, &out)
			for _, c := range out.Chunks {
				if c.ChunkID == chunkID {
					return string(raw), out.Chunks
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("%s: chunk %s never showed up in /api/logs", as, chunkID)
		return "", nil
	}

	body, _ := get("member")
	if !strings.Contains(body, tr.ID) || !strings.Contains(body, "logs view check") {
		t.Errorf("member's logs view is missing the line: %s", body)
	}
	body, chunks := get("staff")
	if strings.Contains(body, "logs view check") || strings.Contains(body, "4111 1111") {
		t.Errorf("staff's logs view contains plaintext: %s", body)
	}
	for _, c := range chunks {
		if c.ChunkID == chunkID {
			t.Logf("staff see chunk %s: status=%s session=%s lines=%d levels=%v", c.ChunkID, c.Status, c.Session, c.Lines, c.Levels)
			if c.Status != "denied" || c.Session != "ses_view" || c.Levels["warn"] == 0 {
				t.Errorf("staff should see the chunk's metadata and a denial: %+v", c)
			}
		}
	}
}

// TestPurge follows demo step 8: purge today, the member's read of the old line
// comes back "destroyed", and a new line gets a new key generation.
func TestPurge(t *testing.T) {
	if os.Getenv("SEALED_LIVE") == "" {
		t.Skip("set SEALED_LIVE=1 with the cluster running")
	}
	d := newDemo()
	time.Sleep(2 * time.Second)
	send := func(msg string) *Trace {
		res := d.Send(Compose{Level: "info", Stream: "stdout", Session: "ses_purge", Msg: msg})
		tr := d.trace(res.Trace)
		if tr == nil {
			t.Fatalf("send failed: %s", res.Status)
		}
		waitFor(t, "the index row", func() bool { return len(d.Derive(tr).byStage["collector"]) >= 3 })
		return tr
	}

	old := send("before the purge")
	if r := readIndexed(d, old, "member").Read; r == nil || len(r.Lines) == 0 {
		t.Fatalf("member cannot read before purge: %+v", r)
	}
	t.Log(PurgeToday().Status)
	time.Sleep(3 * time.Second) // one revocation poll
	if r := readIndexed(d, old, "member").Read; r == nil || r.ChunkStatus != "destroyed" {
		t.Fatalf("after purge: %+v", r)
	}

	time.Sleep(4 * time.Second) // the sidecar caches the public key for 5s
	nw := send("after the purge")
	if r := readIndexed(d, nw, "member").Read; r == nil || len(r.Lines) == 0 {
		t.Fatalf("member cannot read the new line: %+v", r)
	}
	if k := d.Derive(nw).KeyID; k == d.Derive(old).KeyID {
		t.Fatalf("new line reused the purged key %s", k)
	} else {
		t.Logf("old key %s, new key %s", d.Derive(old).KeyID, k)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 180 && !ok(); i++ {
		time.Sleep(250 * time.Millisecond)
	}
	if !ok() {
		t.Fatalf("timed out waiting for %s", what)
	}
}

// readIndexed retries a read until the traced chunk is in the index. ClickHouse
// acknowledges an insert a few milliseconds before a query can see the row.
func readIndexed(d *Demo, tr *Trace, as string) Result {
	var r Result
	for i := 0; i < 20; i++ {
		if r = d.ReadAs(tr, as); r.Read != nil {
			return r
		}
		time.Sleep(250 * time.Millisecond)
	}
	return r
}
