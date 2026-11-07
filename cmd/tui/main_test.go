package main

import (
	"os"
	"testing"
	"time"
)

// TestLifecycle drives the harness against the kind cluster (./up.sh first):
// compose and send a line, read it as three callers, inspect every stage.
func TestLifecycle(t *testing.T) {
	if os.Getenv("SEALED_LIVE") == "" {
		t.Skip("set SEALED_LIVE=1 with the cluster running")
	}
	m := newModel()
	m.w, m.h = 160, 50
	time.Sleep(2 * time.Second)        // let kubectl logs attach before sending
	m.comp.level, m.comp.stream = 3, 1 // error, stderr
	m.comp.session = "ses_test"
	m.comp.attrs = "order_id=88231 tool=charge_card"
	m.comp.msg = "charge failed for card 4111 1111 1111 1111 cvv 123"
	m.send()
	tr := m.cur()
	if tr == nil {
		t.Fatalf("send failed: %s", m.status)
	}
	waitFor := func(what string, ok func() bool) {
		for i := 0; i < 60 && !ok(); i++ {
			time.Sleep(250 * time.Millisecond)
			m.drain()
		}
		if !ok() {
			t.Fatalf("timed out waiting for %s; status=%s events=%d", what, m.status, len(m.events))
		}
	}
	waitFor("the index row", func() bool { return len(m.derive(tr).byStage["collector"]) >= 3 })

	for _, as := range []string{"member", "staff", "other"} {
		msg := m.query(as)().(resultMsg)
		m.Update(msg)
		t.Logf("%-6s → %s", as, msg.status)
	}
	waitFor("aggregator events", func() bool { return len(m.derive(tr).byStage["aggregator"]) >= 9 })
	m.Update(scanStorage(tr)().(resultMsg))
	t.Logf("scan → %s", m.status)

	m.compose = false
	for i, st := range stages {
		m.stage = i
		if fetched[st] {
			m.Update(m.fetch(tr, st)())
		}
		t.Logf("---- %s ----", st)
		for _, l := range m.inspector(tr) {
			t.Logf("  [%s] %s", l.kind, l.text)
		}
	}
	for i, s := range m.derive(tr).steps {
		t.Logf("%02d %-9s %-10s %s", i+1, zoneTag(s.zone), s.stage, s.title)
	}
	m.stage = 1
	t.Log("\n" + m.View())
}

// TestPurge follows walkthrough step 8: purge today, the member's read of the
// old line comes back "destroyed", and a new line gets a new key generation.
func TestPurge(t *testing.T) {
	if os.Getenv("SEALED_LIVE") == "" {
		t.Skip("set SEALED_LIVE=1 with the cluster running")
	}
	m := newModel()
	m.w, m.h = 160, 50
	time.Sleep(2 * time.Second)
	send := func(msg string) *trace {
		m.comp.session, m.comp.msg = "ses_purge", msg
		m.send()
		tr := m.cur()
		if tr == nil {
			t.Fatalf("send failed: %s", m.status)
		}
		for i := 0; i < 60 && len(m.derive(tr).byStage["collector"]) < 3; i++ {
			time.Sleep(250 * time.Millisecond)
			m.drain()
		}
		return tr
	}
	read := func() *readResult { return m.query("member")().(resultMsg).read }

	old := send("before the purge")
	if r := read(); r == nil || len(r.lines) == 0 {
		t.Fatalf("member cannot read before purge: %+v", r)
	}
	t.Log(purgeToday()().(resultMsg).status)
	time.Sleep(3 * time.Second) // one revocation poll
	m.sel = 0
	if r := read(); r == nil || r.chunkStatus != "destroyed" {
		t.Fatalf("after purge: %+v", r)
	}

	time.Sleep(4 * time.Second) // the sidecar caches the public key for 5s
	nw := send("after the purge")
	if r := read(); r == nil || len(r.lines) == 0 {
		t.Fatalf("member cannot read the new line: %+v", r)
	}
	if k := m.derive(nw).keyID; k == m.derive(old).keyID {
		t.Fatalf("new line reused the purged key %s", k)
	} else {
		t.Logf("old key %s, new key %s", m.derive(old).keyID, k)
	}
}
