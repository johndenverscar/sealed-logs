package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
	"sealedlogs/internal/envelope"
	"sealedlogs/internal/events"
	"sealedlogs/internal/scan"
)

// Zone is what a component was holding when it handled a line. The page colours
// every box, step and inspector line by it.
type Zone string

const (
	zPlain  Zone = "plain"
	zSealed Zone = "sealed"
	zKey    Zone = "key"
	zDenied Zone = "denied"
	zInfo   Zone = "info"
)

var stages = []string{"agent", "sidecar", "collector", "bucket", "clickhouse", "aggregator", "keysvc", "viewer"}

// ---- events ----

// ev is one event line from a service's stdout.
type ev map[string]any

func (e ev) s(k string) string { v, _ := e[k].(string); return v }
func (e ev) b(k string) bool   { v, _ := e[k].(bool); return v }
func (e ev) n(k string) int    { v, _ := e[k].(float64); return int(v) }
func (e ev) ts() time.Time     { t, _ := time.Parse(time.RFC3339Nano, e.s("ts")); return t }
func (e ev) kind() string      { return e.s("stage") + "/" + e.s("kind") }
func (e ev) list(k string) []string {
	raw, _ := e[k].([]any)
	var out []string
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// follow streams events from every pod labelled sealed-logs/events=true. kubectl
// logs only picks up pods that exist when it starts, so it is restarted every two
// minutes; duplicates are dropped by event id.
func follow(add func(ev)) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, "kubectl", "--context", config.KubeContext, "-n", config.Namespace,
			"logs", "-f", "--all-containers", "--prefix=false", "--ignore-errors", "--max-log-requests=30",
			"--since=3m", "-l", "sealed-logs/events=true")
		stdout, err := cmd.StdoutPipe()
		if err == nil && cmd.Start() == nil {
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				line := sc.Bytes()
				if !bytes.Contains(line, []byte(events.Tag)) {
					continue
				}
				var e ev
				if json.Unmarshal(line, &e) == nil && e.s("ev") == events.Tag {
					add(e)
				}
			}
			_ = cmd.Wait()
		}
		cancel()
		time.Sleep(time.Second)
	}
}

// ---- model ----

type Step struct {
	TS     time.Time `json:"ts"`
	Stage  string    `json:"stage"`
	Zone   Zone      `json:"zone"`
	Title  string    `json:"title"`
	Detail string    `json:"detail,omitempty"`
}

// Read is what one viewer got back from the aggregator for a traced line.
type Read struct {
	Who         string    `json:"who"`
	URL         string    `json:"url"`
	Sub         string    `json:"sub"`
	Role        string    `json:"role"`
	Project     string    `json:"project"`
	At          time.Time `json:"at"`
	Code        int       `json:"code"`
	Err         string    `json:"error,omitempty"`
	IndexChunks int       `json:"index_chunks"`
	ChunkStatus string    `json:"chunk_status,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	CTPreview   string    `json:"ct_preview,omitempty"`
	ObjectBytes int       `json:"object_bytes"`
	Lines       []string  `json:"lines,omitempty"`
}

// Trace is one line you sent. Everything else about it is derived from events.
type Trace struct {
	ID      string            `json:"id"`
	Level   string            `json:"level"`
	Stream  string            `json:"stream"`
	Session string            `json:"session"`
	Msg     string            `json:"msg"`
	Attrs   map[string]string `json:"attrs"`
	Stdout  string            `json:"stdout"` // the exact line the agent printed
	SentAt  time.Time         `json:"sent_at"`
	local   []Step            // steps the harness saw first-hand: send, reads, scans
	reads   []Read
}

// Derived is what the events say happened to a trace.
type Derived struct {
	ChunkID string
	KeyID   string
	stored  ev
	Steps   []Step
	byStage map[string][]ev
}

// Result is the outcome of an action, shown in the status bar.
type Result struct {
	Status string `json:"status"`
	Zone   Zone   `json:"zone"`
	Trace  string `json:"trace,omitempty"`
	Read   *Read  `json:"read,omitempty"`
}

// Line is one inspector line; Kind picks its colour.
type Line struct {
	Text string `json:"text"`
	Kind string `json:"kind"` // head, plain, sealed, key, denied, dim, ""
}

type Demo struct {
	mu     sync.Mutex
	events []ev
	seen   map[string]bool
	traces []*Trace
	store  *minio.Client
}

func newDemo() *Demo {
	mc, _ := minio.New(config.MinioEndpoint, &minio.Options{Creds: credentials.NewStaticV4(config.MinioUser, config.MinioPass, "")})
	d := &Demo{seen: map[string]bool{}, store: mc}
	go follow(d.add)
	return d
}

func (d *Demo) add(e ev) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen[e.s("id")] {
		return
	}
	d.seen[e.s("id")] = true
	d.events = append(d.events, e)
	sort.SliceStable(d.events, func(i, j int) bool { return d.events[i].ts().Before(d.events[j].ts()) })
	if len(d.events) > 5000 {
		d.events = d.events[len(d.events)-5000:]
	}
}

func (d *Demo) trace(id string) *Trace {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, t := range d.traces {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (d *Demo) record(t *Trace, steps []Step, r *Read) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t.local = append(t.local, steps...)
	if r != nil {
		t.reads = append(t.reads, *r)
	}
}

// ---- the agent ----

type logRecord struct {
	TS        time.Time         `json:"ts"`
	Level     string            `json:"level"`
	Msg       string            `json:"msg"`
	SessionID string            `json:"session_id,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// Compose is what you typed in the composer.
type Compose struct {
	Level   string `json:"level"`
	Stream  string `json:"stream"`
	Session string `json:"session"`
	Attrs   string `json:"attrs"`
	Msg     string `json:"msg"`
}

func parseAttrs(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range strings.Fields(s) {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("attrs must be key=value pairs separated by spaces (got %q)", f)
		}
		out[k] = v
	}
	return out, nil
}

// Send POSTs the composed line to the agent pod, which prints it on the chosen
// stream. From there it is the agent's own output, read by the sidecar.
func (d *Demo) Send(c Compose) Result {
	if strings.TrimSpace(c.Msg) == "" {
		return Result{Status: "the message is empty", Zone: zDenied}
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.Level) {
		c.Level = "info"
	}
	if c.Stream != "stderr" {
		c.Stream = "stdout"
	}
	attrs, err := parseAttrs(c.Attrs)
	if err != nil {
		return Result{Status: err.Error(), Zone: zDenied}
	}
	id := "t_" + randHex(3)
	attrs["trace"] = id
	rec := logRecord{TS: time.Now().UTC(), Level: c.Level, Msg: c.Msg, SessionID: strings.TrimSpace(c.Session), Attrs: attrs}
	line, _ := json.Marshal(rec)
	body, _ := json.Marshal(map[string]string{"stream": c.Stream, "text": string(line)})
	resp, err := http.Post(config.AgentURL+"/log", "application/json", bytes.NewReader(body))
	if err != nil {
		return Result{Status: "agent pod not reachable (is ./up.sh done?): " + err.Error(), Zone: zDenied}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return Result{Status: fmt.Sprintf("agent returned %d", resp.StatusCode), Zone: zDenied}
	}
	session := rec.SessionID
	if session == "" {
		session = "ses_demo" // the sidecar's default for lines without a session
	}
	t := &Trace{ID: id, Level: rec.Level, Stream: c.Stream, Session: session, Msg: rec.Msg, Attrs: rec.Attrs,
		Stdout: string(line), SentAt: rec.TS}
	t.local = append(t.local, Step{t.SentAt, "agent", zPlain, fmt.Sprintf("Agent wrote a line to %s (level %s)", t.Stream, rec.Level), string(line)})
	d.mu.Lock()
	d.traces = append(d.traces, t)
	d.mu.Unlock()
	return Result{Status: "Sent " + id + ". It's sealed and stored within about 2 seconds.", Zone: zInfo, Trace: id}
}

// Derive replays the events for one trace, in timestamp order.
func (d *Demo) Derive(t *Trace) Derived {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := Derived{byStage: map[string][]ev{}}
	var sealedAt time.Time
	for _, e := range d.events {
		if (e.kind() == "sidecar/sealed" || e.kind() == "sdk/sealed") && slices.Contains(e.list("traces"), t.ID) {
			out.ChunkID, out.KeyID, sealedAt = e.s("chunk_id"), e.s("key_id"), e.ts()
		}
	}
	var pubkey ev
	reqs := map[string]bool{}
	keysvcSeen := map[string]bool{}
	add := func(e ev, stage string, z Zone, title, detail string) {
		out.Steps = append(out.Steps, Step{e.ts(), stage, z, title, detail})
	}
	for _, e := range d.events {
		chunk := out.ChunkID != "" && e.s("chunk_id") == out.ChunkID
		key := out.KeyID != "" && e.s("key_id") == out.KeyID
		switch e.kind() {
		case "sidecar/pubkey":
			if key && !e.ts().After(sealedAt) {
				pubkey = e
			}
		case "sidecar/buffered":
			if e.s("trace") == t.ID {
				out.byStage["sidecar"] = append(out.byStage["sidecar"], e)
				add(e, "sidecar", zPlain, fmt.Sprintf("Sidecar read the line from the agent's %s pipe", e.s("stream")),
					fmt.Sprintf("held in memory with %d line(s) for session %s; nothing written to disk", e.n("pending"), e.s("session_id")))
			}
		case "sidecar/sealed", "sdk/sealed":
			if slices.Contains(e.list("traces"), t.ID) {
				out.byStage["sidecar"] = append(out.byStage["sidecar"], e)
				add(e, "sidecar", zSealed, fmt.Sprintf("Sealed into chunk %s (%d lines) with HPKE to %s", e.s("chunk_id"), e.n("lines"), e.s("key_id")),
					fmt.Sprintf("enc=%s…  ct=%s…  %d B plaintext → %d B zstd+sealed", e.s("enc_preview"), e.s("ct_preview"), e.n("pt_bytes"), e.n("ct_bytes")))
			}
		case "sidecar/ship_failed":
			if slices.Contains(e.list("traces"), t.ID) {
				out.byStage["sidecar"] = append(out.byStage["sidecar"], e)
				add(e, "sidecar", zDenied, "Ship failed", e.s("error"))
			}
		case "collector/accepted":
			if chunk {
				out.byStage["collector"] = append(out.byStage["collector"], e)
				add(e, "collector", zSealed, "Collector accepted the sealed envelope from "+e.s("sub"), strings.Join(e.list("checks"), " · "))
			}
		case "collector/stored":
			if chunk {
				out.stored = e
				out.byStage["collector"] = append(out.byStage["collector"], e)
				add(e, "bucket", zSealed, "Sealed chunk stored in the bucket", fmt.Sprintf("s3://%s  (%d B)", e.s("object_key"), e.n("bytes")))
			}
		case "collector/indexed":
			if chunk {
				out.byStage["collector"] = append(out.byStage["collector"], e)
				add(e, "clickhouse", zSealed, "ClickHouse index row written",
					fmt.Sprintf("session %s, level counts %v, key_id %s", e.s("session_id"), e["levels"], e.s("key_id")))
			}
		case "aggregator/chunk":
			if !chunk {
				continue
			}
			reqs[e.s("request_id")] = true
			out.byStage["aggregator"] = append(out.byStage["aggregator"], e)
			z := map[string]Zone{"decrypted": zPlain, "denied": zDenied, "destroyed": zDenied, "error": zDenied}[e.s("status")]
			if e.b("key_cache") && !keysvcSeen[e.s("sub")] {
				// The aggregator reused an earlier keysvc decision for this caller and key.
				keysvcSeen[e.s("sub")] = true
				add(e, "keysvc", ifz(z == zDenied, zDenied, zKey), fmt.Sprintf("Earlier keysvc decision for %s reused from the aggregator's cache: %s", e.s("sub"), e.s("status")),
					"the aggregator reported key_cache=true: no keysvc call this time")
			}
			add(e, "aggregator", z, fmt.Sprintf("Aggregator opened the chunk for %s (%s): %s", e.s("sub"), e.s("role"), e.s("status")),
				strings.TrimSpace(e.s("reason")+ifs(e.b("key_cache"), "  · key_cache=true", "")))
		case "keysvc/unwrap":
			if key && e.ts().After(sealedAt) {
				keysvcSeen[e.s("sub")] = true
				z, verdict := zKey, "ALLOWED"
				if !e.b("allowed") {
					z, verdict = zDenied, "DENIED"
				}
				add(e, "keysvc", z, fmt.Sprintf("KeySvc unwrap of %s for %s (%s): %s", out.KeyID, e.s("sub"), e.s("role"), verdict), e.s("reason")+"  · audited")
			}
		case "keysvc/keys_destroyed":
			if slices.Contains(e.list("key_ids"), out.KeyID) {
				add(e, "keysvc", zDenied, "Key destroyed ("+e.s("reason")+")", "the chunk is still in the bucket and indexed, but nobody can open it")
			}
		}
	}
	if pubkey != nil {
		out.byStage["sidecar"] = append([]ev{pubkey}, out.byStage["sidecar"]...)
	}
	for _, e := range d.events {
		if (e.kind() == "aggregator/index_query" || e.kind() == "aggregator/response") && reqs[e.s("request_id")] {
			out.byStage["aggregator"] = append(out.byStage["aggregator"], e)
		}
	}
	for _, st := range []string{"sidecar", "aggregator"} {
		evs := out.byStage[st]
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].ts().Before(evs[j].ts()) })
	}
	out.Steps = append(out.Steps, t.local...)
	sort.SliceStable(out.Steps, func(i, j int) bool { return out.Steps[i].TS.Before(out.Steps[j].TS) })
	return out
}

// ---- actions ----

var viewers = map[string]string{"member": "u_alice (project member)", "staff": "s_bob@example.com (operator staff)", "other": "u_mallory (member of p_other)"}

// ReadAs queries the aggregator for the trace's session as one of the demo
// identities and reports what that person got back for the traced line.
func (d *Demo) ReadAs(t *Trace, as string) Result {
	if _, ok := viewers[as]; !ok {
		return Result{Status: "unknown viewer " + as, Zone: zDenied}
	}
	chunkID := d.Derive(t).ChunkID
	v := url.Values{"project": {config.DemoProject}, "session": {t.Session}, "since": {"1h"}, "limit": {"500"}}
	tok := auth.DemoToken(as)
	rr := Read{Who: viewers[as], URL: "GET /logs?" + v.Encode(), At: time.Now()}
	if c, err := auth.Parse(tok); err == nil {
		rr.Sub, rr.Role, rr.Project = c.Subject, c.Role, c.Project
	}
	req, _ := http.NewRequest(http.MethodGet, config.AggregatorURL+"/logs?"+v.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{Status: "aggregator: " + err.Error(), Zone: zDenied}
	}
	defer resp.Body.Close()
	rr.Code = resp.StatusCode
	var out struct {
		Chunks []struct {
			ChunkID   string `json:"chunk_id"`
			Status    string `json:"status"`
			Reason    string `json:"reason"`
			CTPreview string `json:"ct_preview"`
			CTBytes   int    `json:"ct_bytes"`
		} `json:"chunks"`
		Lines []struct {
			Msg   string            `json:"msg"`
			Attrs map[string]string `json:"attrs"`
		} `json:"lines"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	rr.Err, rr.IndexChunks = out.Error, len(out.Chunks)
	for _, ch := range out.Chunks {
		if ch.ChunkID == chunkID && chunkID != "" {
			rr.ChunkStatus, rr.Reason, rr.CTPreview, rr.ObjectBytes = ch.Status, ch.Reason, ch.CTPreview, ch.CTBytes
		}
	}
	for _, l := range out.Lines {
		if l.Attrs["trace"] == t.ID {
			rr.Lines = append(rr.Lines, l.Msg)
		}
	}
	who := viewers[as]
	switch {
	case len(rr.Lines) > 0:
		d.record(t, []Step{{time.Now(), "viewer", zPlain, "Viewer " + who + " received the decrypted line", rr.Lines[0]}}, &rr)
		return Result{Status: who + " can read the line", Zone: zPlain, Trace: t.ID, Read: &rr}
	case rr.ChunkStatus != "":
		d.record(t, []Step{{time.Now(), "viewer", zDenied, "Viewer " + who + " got no plaintext", "chunk status " + rr.ChunkStatus + ", ct=" + rr.CTPreview + "…"}}, &rr)
		return Result{Status: who + " got ciphertext only", Zone: zDenied, Trace: t.ID, Read: &rr}
	}
	return Result{Status: fmt.Sprintf("%s: the traced chunk isn't indexed yet (%d chunks in session %s)", who, len(out.Chunks), t.Session), Zone: zInfo, Trace: t.ID}
}

// Scan reads every stored object and index row looking for card numbers, SSNs
// and, when a trace is given, its id and exact message.
func (d *Demo) Scan(t *Trace) Result {
	var extra [][]byte
	what := ""
	if t != nil {
		what = ", trace id"
		extra = append(extra, []byte(t.ID))
		if len(t.Msg) >= 4 {
			extra = append(extra, []byte(t.Msg))
			what += " and your exact message"
		}
	}
	r, err := scan.Run(context.Background(), extra...)
	if err != nil {
		return Result{Status: "scan: " + err.Error(), Zone: zDenied}
	}
	z := ifz(r.ObjectHits+r.RowHits > 0, zDenied, zSealed)
	res := Result{Status: "Raw storage scan for card numbers, SSNs" + what + ": " + r.String(), Zone: z}
	if t != nil {
		res.Trace = t.ID
		d.record(t, []Step{{time.Now(), "bucket", z, "Raw storage scan (what an attacker with the bucket and ClickHouse sees)", r.String()}}, nil)
	}
	return res
}

// PurgeToday destroys the demo project's keys for the current UTC day.
func PurgeToday() Result {
	day := time.Now().UTC().Format("2006-01-02")
	body, _ := json.Marshal(map[string]string{"project": config.DemoProject, "from": day, "to": day})
	req, _ := http.NewRequest(http.MethodPost, config.KeysvcURL+"/purge", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.DemoToken("member"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{Status: "keysvc: " + err.Error(), Zone: zDenied}
	}
	defer resp.Body.Close()
	var out struct{ Destroyed []string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return Result{Status: fmt.Sprintf("Purged %s: destroyed %d key(s). New logs get a fresh key generation.", day, len(out.Destroyed)), Zone: zDenied}
}

// SendPlaintext posts plaintext lines to the collector, like an old client would.
func SendPlaintext() Result {
	body, _ := json.Marshal(map[string]any{
		"meta":  map[string]any{"project": config.DemoProject, "chunk_id": "c_plain"},
		"lines": []map[string]string{{"msg": "card 4111 1111 1111 1111"}},
	})
	req, _ := http.NewRequest(http.MethodPost, config.CollectorURL+"/chunks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.DemoToken("producer"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{Status: "collector: " + err.Error(), Zone: zDenied}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return Result{Status: fmt.Sprintf("old SDK sent plaintext → collector %d %s", resp.StatusCode, strings.TrimSpace(string(b))), Zone: zDenied}
}

// ---- inspector ----

func head(s string) Line          { return Line{s, "head"} }
func lin(kind, s string) Line     { return Line{s, kind} }
func dim(f string, a ...any) Line { return Line{fmt.Sprintf(f, a...), "dim"} }

// fetched stages are read from the real stores.
var fetched = map[string]bool{"bucket": true, "clickhouse": true, "keysvc": true}

// Inspect returns what the selected component received and produced for a trace.
func (d *Demo) Inspect(t *Trace, st string) []Line {
	dv := d.Derive(t)
	switch st {
	case "bucket":
		return d.fetchBucket(strings.TrimPrefix(dv.stored.s("object_key"), config.Bucket+"/"), t.Msg)
	case "clickhouse":
		return fetchClickHouse(dv.ChunkID, t.Msg)
	case "keysvc":
		return fetchKeysvc(dv.KeyID)
	case "agent":
		return []Line{
			head(fmt.Sprintf("POST %s/log → agent prints on %s  (%d B)", config.AgentURL, t.Stream, len(t.Stdout)+1)),
			lin("plain", t.Stdout),
		}
	case "viewer":
		d.mu.Lock()
		reads := slices.Clone(t.reads)
		d.mu.Unlock()
		if len(reads) == 0 {
			return []Line{dim("Nobody has read this line yet. Use the Read as buttons.")}
		}
		var ls []Line
		for i := len(reads) - 1; i >= 0; i-- {
			r := reads[i]
			ls = append(ls, head(fmt.Sprintf("%s  %s  %s", r.At.Local().Format("15:04:05"), r.Who, r.URL)))
			switch {
			case r.Err != "":
				ls = append(ls, lin("denied", fmt.Sprintf("%d %s", r.Code, r.Err)))
			case len(r.Lines) > 0:
				for _, l := range r.Lines {
					ls = append(ls, lin("plain", l))
				}
			case r.ChunkStatus != "":
				ls = append(ls, lin("denied", fmt.Sprintf("no plaintext: chunk %s (%s)", r.ChunkStatus, r.Reason)),
					lin("sealed", fmt.Sprintf("ct=%s…  (object %d B)", r.CTPreview, r.ObjectBytes)))
			default:
				ls = append(ls, dim("chunk not found yet"))
			}
		}
		return ls
	}
	evs := dv.byStage[st]
	if len(evs) == 0 {
		return []Line{dim("No events from %s for this line yet.", st)}
	}
	return eventLines(evs)
}

func (d *Demo) fetchBucket(objectKey, msg string) []Line {
	if objectKey == "" {
		return []Line{dim("Waiting for the collector to report a stored chunk.")}
	}
	obj, err := d.store.GetObject(context.Background(), config.Bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return []Line{lin("denied", "bucket: "+err.Error())}
	}
	defer obj.Close()
	raw, err := io.ReadAll(obj)
	if err != nil {
		return []Line{lin("denied", "bucket: "+err.Error())}
	}
	ls := []Line{head(fmt.Sprintf("STORED  s3://%s/%s  (%d B)", config.Bucket, objectKey, len(raw)))}
	var ck envelope.Chunk
	if err := json.Unmarshal(raw, &ck); err != nil {
		return append(ls, lin("denied", "not a chunk: "+err.Error()))
	}
	meta, _ := json.MarshalIndent(ck.Meta, "  ", "  ")
	ls = append(ls, dim(`{"meta":`), lin("", "  "+string(meta)),
		dim(` "sealed": {"v": %d, "key_id": %q,`, ck.Sealed.V, ck.Sealed.KeyID),
		lin("sealed", fmt.Sprintf(`   "enc": %s…  (%d B)`, events.Preview(ck.Sealed.Enc, 12), len(ck.Sealed.Enc))),
		lin("sealed", fmt.Sprintf(`   "ct":  %s…  (%d B)`, events.Preview(ck.Sealed.CT, 12), len(ck.Sealed.CT))),
		dim(`}}`), head("CHECK  is your message text in this object?"), containsLine(raw, msg))
	return ls
}

func containsLine(raw []byte, msg string) Line {
	if bytes.Contains(raw, []byte(msg)) {
		return lin("denied", "FOUND: plaintext is in storage")
	}
	return lin("sealed", fmt.Sprintf("message text: not found (%d bytes searched for %q)", len(raw), truncate(msg, 40)))
}

func fetchClickHouse(chunkID, msg string) []Line {
	if chunkID == "" {
		return []Line{dim("Waiting for the sidecar to report a sealed chunk.")}
	}
	q := url.Values{
		"query":    {"SELECT * FROM sealed.log_chunks WHERE chunk_id = {id:String} FORMAT Vertical"},
		"param_id": {chunkID}, "user": {config.CHUser}, "password": {config.CHPass},
	}
	resp, err := http.Get(config.CHHTTP + "/?" + q.Encode())
	if err != nil {
		return []Line{lin("denied", "clickhouse: "+err.Error())}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ls := []Line{head("STORED  SELECT * FROM sealed.log_chunks WHERE chunk_id = '" + chunkID + "'")}
	body := strings.TrimSpace(string(b))
	if body == "" {
		return append(ls, dim("no row yet"))
	}
	for _, l := range strings.Split(body, "\n") {
		if !strings.HasPrefix(l, "Row ") && !strings.HasPrefix(l, "──") && strings.TrimSpace(l) != "" {
			ls = append(ls, lin("", l))
		}
	}
	return append(ls, head("CHECK  is your message text in this row?"), containsLine(b, msg))
}

func fetchKeysvc(keyID string) []Line {
	if keyID == "" {
		return []Line{dim("Waiting for the sidecar to report a sealed chunk.")}
	}
	get := func(path string, out any) error {
		req, _ := http.NewRequest(http.MethodGet, config.KeysvcURL+path, nil)
		req.Header.Set("Authorization", "Bearer "+auth.DemoToken("member"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(out)
	}
	var keys, audit []map[string]any
	project, _, _ := strings.Cut(keyID, "/")
	if err := get("/keys?project="+url.QueryEscape(project), &keys); err != nil {
		return []Line{lin("denied", "keysvc: "+err.Error())}
	}
	_ = get("/audit?limit=12&key_id="+url.QueryEscape(keyID), &audit)

	ls := []Line{head("AUDIT  requests for " + keyID + ", newest first")}
	if len(audit) == 0 {
		ls = append(ls, dim("none yet"))
	}
	for _, a := range audit {
		ts, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(a["ts"]))
		allowed := a["allowed"] == true
		ls = append(ls, lin(ifs(allowed, "key", "denied"), fmt.Sprintf("%s  %-6s %-5s %-18s %-7s %-8s %s", ts.Local().Format("15:04:05"),
			a["action"], ifs(allowed, "ALLOW", "DENY"), a["sub"], a["role"], a["caller_project"], a["reason"])))
	}
	ls = append(ls, head("KEY RECORD"))
	for _, k := range keys {
		if k["key_id"] != keyID {
			continue
		}
		ls = append(ls,
			lin(ifs(strings.HasPrefix(fmt.Sprint(k["status"]), "destroyed"), "denied", "key"), fmt.Sprintf("%s  %s", k["key_id"], k["status"])),
			dim("created     %s", k["created_at"]),
			lin("key", fmt.Sprintf("public key  %s", k["pub_hex"])),
			lin("sealed", fmt.Sprintf("private key %s  (%s)", k["wrapped"], k["wrapper"])),
		)
	}
	return ls
}

// eventLines renders events exactly as the services reported them.
func eventLines(evs []ev) []Line {
	var ls []Line
	for _, e := range evs {
		ls = append(ls, head(fmt.Sprintf("%s  %s", e.ts().Local().Format("15:04:05.000"), e.kind())))
		var keys []string
		for k := range e {
			if !slices.Contains([]string{"ev", "id", "ts", "stage", "kind"}, k) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			var s string
			switch x := e[k].(type) {
			case string:
				s = x
			case map[string]any:
				b, _ := json.MarshalIndent(x, "    ", "  ")
				s = string(b)
			default:
				b, _ := json.Marshal(x)
				s = string(b)
			}
			kind := ""
			switch {
			case strings.HasSuffix(k, "_preview"):
				kind = "sealed"
			case k == "status" && s != "decrypted", k == "reason" || k == "error":
				kind = "denied"
			}
			ls = append(ls, lin(kind, fmt.Sprintf("  %-14s %s", k, s)))
		}
	}
	return ls
}

// ---- helpers ----

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func ifs(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

func ifz(c bool, a, b Zone) Zone {
	if c {
		return a
	}
	return b
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
