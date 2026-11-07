// tui is the demo harness. You play the customer's agent: write a log line, POST
// it to the agent pod, which prints it on stdout or stderr. Every service reports
// what it received and produced as JSON events on its own stdout; the TUI follows
// them with kubectl logs. Bucket, ClickHouse and keysvc panels are read live from
// the stores. Nothing in the inspector is asserted by the TUI itself.
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
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
	"sealedlogs/internal/envelope"
	"sealedlogs/internal/events"
	"sealedlogs/internal/scan"
)

// ---- styles ----

var (
	cPlain  = lipgloss.Color("#F0A14A")
	cSealed = lipgloss.Color("#4CC5B9")
	cKey    = lipgloss.Color("#9A9DF5")
	cBad    = lipgloss.Color("#F28B82")
	cDim    = lipgloss.Color("#5A6672")
	cText   = lipgloss.Color("#E4E9EE")

	sTitle = lipgloss.NewStyle().Bold(true).Foreground(cText)
	sDim   = lipgloss.NewStyle().Foreground(cDim)
	sPanel = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cDim).Padding(0, 1)
	sFocus = sPanel.BorderForeground(cText)
)

type zone int

const (
	zPlain zone = iota
	zSealed
	zKey
	zDenied
	zInfo
)

func zoneColor(z zone) lipgloss.Color {
	switch z {
	case zPlain:
		return cPlain
	case zSealed:
		return cSealed
	case zKey:
		return cKey
	case zDenied:
		return cBad
	}
	return cDim
}

func zoneTag(z zone) string {
	return map[zone]string{zPlain: "PLAINTEXT", zSealed: "SEALED", zKey: "KEY", zDenied: "DENIED"}[z] + ifs(z == zInfo, "INFO", "")
}

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
func follow(out chan<- ev) {
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
					out <- e
				}
			}
			_ = cmd.Wait()
		}
		cancel()
		time.Sleep(time.Second)
	}
}

// ---- model ----

type step struct {
	ts     time.Time
	stage  string
	zone   zone
	title  string
	detail string
}

type readResult struct {
	who, url            string
	sub, role, project  string
	at                  time.Time
	code                int
	err                 string
	indexChunks         int
	chunkStatus, reason string
	ctPreview           string
	objectBytes         int
	lines               []string
}

// trace is one line you sent. Everything else about it is derived from events.
type trace struct {
	id                          string
	level, stream, session, msg string
	attrs                       map[string]string
	stdout                      string // the exact line the agent printed
	sentAt                      time.Time
	local                       []step // steps the TUI saw first-hand: send, reads, scans
	reads                       []readResult
}

// derived is what the events say happened to a trace.
type derived struct {
	chunkID, keyID string
	stored         ev
	steps          []step
	byStage        map[string][]ev
}

var (
	levels     = []string{"debug", "info", "warn", "error"}
	streams    = []string{"stdout", "stderr"}
	fieldNames = []string{"level", "stream", "session_id", "attrs", "message"}
)

const (
	fLevel = iota
	fStream
	fSession
	fAttrs
	fMsg
)

type composer struct {
	level, stream, field int
	session, attrs, msg  string
}

func (c *composer) text() *string {
	switch c.field {
	case fSession:
		return &c.session
	case fAttrs:
		return &c.attrs
	case fMsg:
		return &c.msg
	}
	return nil
}

// iline is one inspector line; kind picks its color.
type iline struct {
	text string
	kind string // head, plain, sealed, key, denied, dim, ""
}

type inspCache struct {
	lines   []iline
	at      time.Time
	loading bool
}

type model struct {
	w, h    int
	traces  []*trace
	sel     int
	stage   int
	scroll  int
	compose bool
	comp    composer
	status  string
	statusZ zone
	started time.Time

	in     chan ev
	events []ev
	seen   map[string]bool

	insp  map[string]*inspCache
	store *minio.Client
}

type tickMsg struct{}
type resultMsg struct {
	status  string
	z       zone
	traceID string
	steps   []step
	read    *readResult
}
type inspMsg struct {
	key   string
	lines []iline
}

func newModel() *model {
	mc, _ := minio.New(config.MinioEndpoint, &minio.Options{Creds: credentials.NewStaticV4(config.MinioUser, config.MinioPass, "")})
	m := &model{
		in: make(chan ev, 4096), seen: map[string]bool{}, insp: map[string]*inspCache{}, store: mc,
		compose: true, started: time.Now(),
		comp: composer{level: 1, field: fMsg, session: "ses_demo", attrs: "order_id=88231 caller=caller_1",
			msg: "payment captured card=4111 1111 1111 1111 exp=12/28"},
		status: "Write a log line as the customer's agent and press enter. Esc switches to navigation.", statusZ: zInfo,
	}
	go follow(m.in)
	return m
}

func main() {
	if _, err := tea.NewProgram(newModel(), tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (m *model) Init() tea.Cmd { return tick() }

func tick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *model) cur() *trace {
	if len(m.traces) == 0 {
		return nil
	}
	return m.traces[m.sel]
}

func (m *model) byID(id string) *trace {
	for _, t := range m.traces {
		if t.id == id {
			return t
		}
	}
	return nil
}

// drain moves followed events into the model, in timestamp order.
func (m *model) drain() {
	added := false
	for {
		select {
		case e := <-m.in:
			if m.seen[e.s("id")] {
				continue
			}
			m.seen[e.s("id")] = true
			m.events = append(m.events, e)
			added = true
			if e.kind() == "collector/rejected" && e.ts().After(m.started) {
				m.status, m.statusZ = "collector rejected: "+e.s("reason"), zDenied
			}
		default:
			if added {
				sort.SliceStable(m.events, func(i, j int) bool { return m.events[i].ts().Before(m.events[j].ts()) })
				if len(m.events) > 5000 {
					m.events = m.events[len(m.events)-5000:]
				}
			}
			return
		}
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tickMsg:
		m.drain()
		return m, tea.Batch(tick(), m.maybeFetch())
	case resultMsg:
		m.status, m.statusZ = msg.status, msg.z
		t := m.byID(msg.traceID)
		if t == nil {
			t = m.cur()
		}
		if t != nil {
			t.local = append(t.local, msg.steps...)
			if msg.read != nil {
				t.reads = append(t.reads, *msg.read)
			}
		}
	case inspMsg:
		m.insp[msg.key] = &inspCache{lines: msg.lines, at: time.Now()}
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.compose {
			return m, m.composeKey(msg)
		}
		return m, m.navKey(msg)
	}
	return m, nil
}

func (m *model) composeKey(k tea.KeyMsg) tea.Cmd {
	c := &m.comp
	switch k.String() {
	case "esc":
		m.compose = false
	case "tab", "down":
		c.field = (c.field + 1) % len(fieldNames)
	case "shift+tab", "up":
		c.field = (c.field + len(fieldNames) - 1) % len(fieldNames)
	case "enter":
		return m.send()
	case "left", "right":
		d := ifn(k.String() == "left", -1, 1)
		switch c.field {
		case fLevel:
			c.level = (c.level + d + len(levels)) % len(levels)
		case fStream:
			c.stream = (c.stream + d + len(streams)) % len(streams)
		}
	case "backspace":
		if p := c.text(); p != nil && *p != "" {
			r := []rune(*p)
			*p = string(r[:len(r)-1])
		}
	case "ctrl+u":
		if p := c.text(); p != nil {
			*p = ""
		}
	default:
		if p := c.text(); p != nil {
			switch k.Type {
			case tea.KeyRunes:
				*p += string(k.Runes)
			case tea.KeySpace:
				*p += " "
			}
		}
	}
	return nil
}

func (m *model) navKey(k tea.KeyMsg) tea.Cmd {
	switch s := k.String(); s {
	case "q":
		return tea.Quit
	case "tab", "i", "c", "enter":
		m.compose = true
	case "left", "h":
		m.stage, m.scroll = (m.stage+len(stages)-1)%len(stages), 0
	case "right", "l":
		m.stage, m.scroll = (m.stage+1)%len(stages), 0
	case "1", "2", "3", "4", "5", "6", "7", "8":
		m.stage, m.scroll = int(s[0]-'1'), 0
	case "up", "k":
		m.scroll = max(0, m.scroll-1)
	case "down", "j":
		m.scroll++
	case "pgup":
		m.scroll = max(0, m.scroll-10)
	case "pgdown":
		m.scroll += 10
	case "[":
		if m.sel > 0 {
			m.sel, m.scroll = m.sel-1, 0
		}
	case "]":
		if m.sel < len(m.traces)-1 {
			m.sel, m.scroll = m.sel+1, 0
		}
	case "m":
		return m.query("member")
	case "s":
		return m.query("staff")
	case "o":
		return m.query("other")
	case "g":
		m.status, m.statusZ = "scanning the bucket and ClickHouse…", zInfo
		return scanStorage(m.cur())
	case "p":
		return purgeToday()
	case "x":
		return sendPlaintext()
	case "r":
		if t := m.cur(); t != nil {
			delete(m.insp, t.id+"/"+stages[m.stage])
		}
	}
	return nil
}

// ---- the agent ----

type logRecord struct {
	TS        time.Time         `json:"ts"`
	Level     string            `json:"level"`
	Msg       string            `json:"msg"`
	SessionID string            `json:"session_id,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
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

func (m *model) record(traceID string) (logRecord, error) {
	c := m.comp
	attrs, err := parseAttrs(c.attrs)
	if err != nil {
		return logRecord{}, err
	}
	attrs["trace"] = traceID
	return logRecord{TS: time.Now().UTC(), Level: levels[c.level], Msg: c.msg, SessionID: strings.TrimSpace(c.session), Attrs: attrs}, nil
}

// send POSTs the composed line to the agent pod, which prints it on the chosen
// stream. From there it is the agent's own output, read by the sidecar.
func (m *model) send() tea.Cmd {
	c := m.comp
	if strings.TrimSpace(c.msg) == "" {
		m.status, m.statusZ = "the message is empty", zDenied
		return nil
	}
	id := "t_" + randHex(3)
	rec, err := m.record(id)
	if err != nil {
		m.status, m.statusZ = err.Error(), zDenied
		return nil
	}
	line, _ := json.Marshal(rec)
	body, _ := json.Marshal(map[string]string{"stream": streams[c.stream], "text": string(line)})
	resp, err := http.Post(config.AgentURL+"/log", "application/json", bytes.NewReader(body))
	if err != nil {
		m.status, m.statusZ = "agent pod not reachable (./up.sh): "+err.Error(), zDenied
		return nil
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		m.status, m.statusZ = fmt.Sprintf("agent returned %d", resp.StatusCode), zDenied
		return nil
	}
	session := rec.SessionID
	if session == "" {
		session = "ses_demo" // the sidecar's default for lines without a session
	}
	t := &trace{id: id, level: rec.Level, stream: streams[c.stream], session: session, msg: rec.Msg, attrs: rec.Attrs,
		stdout: string(line), sentAt: rec.TS}
	t.local = append(t.local, step{t.sentAt, "agent", zPlain, fmt.Sprintf("Agent wrote a line to %s (level %s)", t.stream, rec.Level), string(line)})
	m.traces = append(m.traces, t)
	m.sel = len(m.traces) - 1
	m.status, m.statusZ = "sent "+id+". It seals within 2 s. Esc, then ←/→ to inspect each stage and m/s/o to read it.", zInfo
	return nil
}

// derive replays the events for one trace, in timestamp order.
func (m *model) derive(t *trace) derived {
	d := derived{byStage: map[string][]ev{}}
	var sealedAt time.Time
	for _, e := range m.events {
		if (e.kind() == "sidecar/sealed" || e.kind() == "sdk/sealed") && slices.Contains(e.list("traces"), t.id) {
			d.chunkID, d.keyID, sealedAt = e.s("chunk_id"), e.s("key_id"), e.ts()
		}
	}
	var pubkey ev
	reqs := map[string]bool{}
	keysvcSeen := map[string]bool{}
	add := func(e ev, stage string, z zone, title, detail string) {
		d.steps = append(d.steps, step{e.ts(), stage, z, title, detail})
	}
	for _, e := range m.events {
		chunk := d.chunkID != "" && e.s("chunk_id") == d.chunkID
		key := d.keyID != "" && e.s("key_id") == d.keyID
		switch e.kind() {
		case "sidecar/pubkey":
			if key && !e.ts().After(sealedAt) {
				pubkey = e
			}
		case "sidecar/buffered":
			if e.s("trace") == t.id {
				d.byStage["sidecar"] = append(d.byStage["sidecar"], e)
				add(e, "sidecar", zPlain, fmt.Sprintf("Sidecar read the line from the agent's %s FIFO", e.s("stream")),
					fmt.Sprintf("held in memory with %d line(s) for session %s; nothing written to disk", e.n("pending"), e.s("session_id")))
			}
		case "sidecar/sealed", "sdk/sealed":
			if slices.Contains(e.list("traces"), t.id) {
				d.byStage["sidecar"] = append(d.byStage["sidecar"], e)
				add(e, "sidecar", zSealed, fmt.Sprintf("Sealed into chunk %s (%d lines) with HPKE to %s", e.s("chunk_id"), e.n("lines"), e.s("key_id")),
					fmt.Sprintf("enc=%s…  ct=%s…  %d B plaintext → %d B zstd+sealed", e.s("enc_preview"), e.s("ct_preview"), e.n("pt_bytes"), e.n("ct_bytes")))
			}
		case "sidecar/ship_failed":
			if slices.Contains(e.list("traces"), t.id) {
				d.byStage["sidecar"] = append(d.byStage["sidecar"], e)
				add(e, "sidecar", zDenied, "Ship failed", e.s("error"))
			}
		case "collector/accepted":
			if chunk {
				d.byStage["collector"] = append(d.byStage["collector"], e)
				add(e, "collector", zSealed, "Collector accepted the sealed envelope from "+e.s("sub"), strings.Join(e.list("checks"), " · "))
			}
		case "collector/stored":
			if chunk {
				d.stored = e
				d.byStage["collector"] = append(d.byStage["collector"], e)
				add(e, "bucket", zSealed, "Sealed chunk stored in the bucket", fmt.Sprintf("s3://%s  (%d B)", e.s("object_key"), e.n("bytes")))
			}
		case "collector/indexed":
			if chunk {
				d.byStage["collector"] = append(d.byStage["collector"], e)
				add(e, "clickhouse", zSealed, "ClickHouse index row written",
					fmt.Sprintf("session %s, level counts %v, key_id %s", e.s("session_id"), e["levels"], e.s("key_id")))
			}
		case "aggregator/chunk":
			if !chunk {
				continue
			}
			reqs[e.s("request_id")] = true
			d.byStage["aggregator"] = append(d.byStage["aggregator"], e)
			z := map[string]zone{"decrypted": zPlain, "denied": zDenied, "destroyed": zDenied, "error": zDenied}[e.s("status")]
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
				add(e, "keysvc", z, fmt.Sprintf("KeySvc unwrap of %s for %s (%s): %s", d.keyID, e.s("sub"), e.s("role"), verdict), e.s("reason")+"  · audited")
			}
		case "keysvc/keys_destroyed":
			if slices.Contains(e.list("key_ids"), d.keyID) {
				add(e, "keysvc", zDenied, "Key destroyed ("+e.s("reason")+")", "the chunk is still in the bucket and indexed, but nobody can open it")
			}
		}
	}
	if pubkey != nil {
		d.byStage["sidecar"] = append([]ev{pubkey}, d.byStage["sidecar"]...)
	}
	for _, e := range m.events {
		if (e.kind() == "aggregator/index_query" || e.kind() == "aggregator/response") && reqs[e.s("request_id")] {
			d.byStage["aggregator"] = append(d.byStage["aggregator"], e)
		}
	}
	for _, st := range []string{"sidecar", "aggregator"} {
		evs := d.byStage[st]
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].ts().Before(evs[j].ts()) })
	}
	d.steps = append(d.steps, t.local...)
	sort.SliceStable(d.steps, func(i, j int) bool { return d.steps[i].ts.Before(d.steps[j].ts) })
	return d
}

// ---- actions ----

var viewers = map[string]string{"member": "u_alice (project member)", "staff": "s_bob@example.com (operator staff)", "other": "u_mallory (member of p_other)"}

func (m *model) query(as string) tea.Cmd {
	t := m.cur()
	if t == nil {
		m.status, m.statusZ = "send a line first (tab to compose)", zInfo
		return nil
	}
	id, chunkID, session := t.id, m.derive(t).chunkID, t.session
	return func() tea.Msg {
		v := url.Values{"project": {config.DemoProject}, "session": {session}, "since": {"1h"}, "limit": {"500"}}
		tok := auth.DemoToken(as)
		rr := readResult{who: viewers[as], url: "GET /logs?" + v.Encode(), at: time.Now()}
		if c, err := auth.Parse(tok); err == nil {
			rr.sub, rr.role, rr.project = c.Subject, c.Role, c.Project
		}
		req, _ := http.NewRequest(http.MethodGet, config.AggregatorURL+"/logs?"+v.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return resultMsg{status: "aggregator: " + err.Error(), z: zDenied}
		}
		defer resp.Body.Close()
		rr.code = resp.StatusCode
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
		rr.err, rr.indexChunks = out.Error, len(out.Chunks)
		for _, ch := range out.Chunks {
			if ch.ChunkID == chunkID && chunkID != "" {
				rr.chunkStatus, rr.reason, rr.ctPreview, rr.objectBytes = ch.Status, ch.Reason, ch.CTPreview, ch.CTBytes
			}
		}
		for _, l := range out.Lines {
			if l.Attrs["trace"] == id {
				rr.lines = append(rr.lines, l.Msg)
			}
		}
		who := viewers[as]
		switch {
		case len(rr.lines) > 0:
			return resultMsg{status: who + " can read the line", z: zPlain, traceID: id, read: &rr,
				steps: []step{{time.Now(), "viewer", zPlain, "Viewer " + who + " received the decrypted line", rr.lines[0]}}}
		case rr.chunkStatus != "":
			return resultMsg{status: who + " got ciphertext only", z: zDenied, traceID: id, read: &rr,
				steps: []step{{time.Now(), "viewer", zDenied, "Viewer " + who + " got no plaintext", "chunk status " + rr.chunkStatus + ", ct=" + rr.ctPreview + "…"}}}
		}
		return resultMsg{status: fmt.Sprintf("%s: the traced chunk isn't indexed yet (%d chunks in session %s)", who, len(out.Chunks), session), z: zInfo, traceID: id}
	}
}

func scanStorage(t *trace) tea.Cmd {
	var extra [][]byte
	var id, what string
	if t != nil {
		id, what = t.id, ", trace id"
		extra = append(extra, []byte(t.id))
		if len(t.msg) >= 4 {
			extra = append(extra, []byte(t.msg))
			what += " and your exact message"
		}
	}
	return func() tea.Msg {
		r, err := scan.Run(context.Background(), extra...)
		if err != nil {
			return resultMsg{status: "scan: " + err.Error(), z: zDenied}
		}
		z := ifz(r.ObjectHits+r.RowHits > 0, zDenied, zSealed)
		return resultMsg{status: "raw storage scan for card, SSN" + what + ": " + r.String(), z: z, traceID: id,
			steps: []step{{time.Now(), "bucket", z, "Raw storage scan (what an attacker with the bucket and ClickHouse sees)", r.String()}}}
	}
}

func purgeToday() tea.Cmd {
	return func() tea.Msg {
		day := time.Now().UTC().Format("2006-01-02")
		body, _ := json.Marshal(map[string]string{"project": config.DemoProject, "from": day, "to": day})
		req, _ := http.NewRequest(http.MethodPost, config.KeysvcURL+"/purge", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+auth.DemoToken("member"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return resultMsg{status: "keysvc: " + err.Error(), z: zDenied}
		}
		defer resp.Body.Close()
		var out struct{ Destroyed []string }
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resultMsg{status: fmt.Sprintf("purged %s: destroyed %d key(s). New logs get a fresh key generation.", day, len(out.Destroyed)), z: zDenied}
	}
}

func sendPlaintext() tea.Cmd {
	return func() tea.Msg {
		body, _ := json.Marshal(map[string]any{
			"meta":  map[string]any{"project": config.DemoProject, "chunk_id": "c_plain"},
			"lines": []map[string]string{{"msg": "card 4111 1111 1111 1111"}},
		})
		req, _ := http.NewRequest(http.MethodPost, config.CollectorURL+"/chunks", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+auth.DemoToken("producer"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return resultMsg{status: "collector: " + err.Error(), z: zDenied}
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resultMsg{status: fmt.Sprintf("old SDK sent plaintext → collector %d %s", resp.StatusCode, strings.TrimSpace(string(b))), z: zDenied}
	}
}

// ---- inspector ----

func head(s string) iline          { return iline{s, "head"} }
func lin(kind, s string) iline     { return iline{s, kind} }
func dim(f string, a ...any) iline { return iline{fmt.Sprintf(f, a...), "dim"} }

// fetched stages are read from the real stores.
var fetched = map[string]bool{"bucket": true, "clickhouse": true, "keysvc": true}

func (m *model) maybeFetch() tea.Cmd {
	t := m.cur()
	st := stages[m.stage]
	if t == nil || !fetched[st] {
		return nil
	}
	key := t.id + "/" + st
	if c := m.insp[key]; c != nil && (c.loading || time.Since(c.at) < 2*time.Second) {
		return nil
	}
	lines := []iline{dim("loading…")}
	if prev := m.insp[key]; prev != nil {
		lines = prev.lines
	}
	m.insp[key] = &inspCache{lines: lines, loading: true}
	return m.fetch(t, st)
}

func (m *model) fetch(t *trace, st string) tea.Cmd {
	d := m.derive(t)
	key, msg, store := t.id+"/"+st, t.msg, m.store
	objectKey := strings.TrimPrefix(d.stored.s("object_key"), config.Bucket+"/")
	return func() tea.Msg {
		var ls []iline
		switch st {
		case "bucket":
			ls = fetchBucket(store, objectKey, msg)
		case "clickhouse":
			ls = fetchClickHouse(d.chunkID, msg)
		case "keysvc":
			ls = fetchKeysvc(d.keyID)
		}
		return inspMsg{key: key, lines: ls}
	}
}

func fetchBucket(store *minio.Client, objectKey, msg string) []iline {
	if objectKey == "" {
		return []iline{dim("Waiting for the collector to report a stored chunk.")}
	}
	obj, err := store.GetObject(context.Background(), config.Bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return []iline{lin("denied", "bucket: "+err.Error())}
	}
	defer obj.Close()
	raw, err := io.ReadAll(obj)
	if err != nil {
		return []iline{lin("denied", "bucket: "+err.Error())}
	}
	ls := []iline{head(fmt.Sprintf("STORED  s3://%s/%s  (%d B)", config.Bucket, objectKey, len(raw)))}
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

func containsLine(raw []byte, msg string) iline {
	if bytes.Contains(raw, []byte(msg)) {
		return lin("denied", "FOUND: plaintext is in storage")
	}
	return lin("sealed", fmt.Sprintf("not found: %d bytes searched for %q", len(raw), truncate(msg, 40)))
}

func fetchClickHouse(chunkID, msg string) []iline {
	if chunkID == "" {
		return []iline{dim("Waiting for the sidecar to report a sealed chunk.")}
	}
	q := url.Values{
		"query":    {"SELECT * FROM sealed.log_chunks WHERE chunk_id = {id:String} FORMAT Vertical"},
		"param_id": {chunkID}, "user": {config.CHUser}, "password": {config.CHPass},
	}
	resp, err := http.Get(config.CHHTTP + "/?" + q.Encode())
	if err != nil {
		return []iline{lin("denied", "clickhouse: "+err.Error())}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ls := []iline{head("STORED  SELECT * FROM sealed.log_chunks WHERE chunk_id = '" + chunkID + "'")}
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

func fetchKeysvc(keyID string) []iline {
	if keyID == "" {
		return []iline{dim("Waiting for the sidecar to report a sealed chunk.")}
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
		return []iline{lin("denied", "keysvc: "+err.Error())}
	}
	_ = get("/audit?limit=12&key_id="+url.QueryEscape(keyID), &audit)

	ls := []iline{head("AUDIT  requests for " + keyID + ", newest first")}
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
func eventLines(evs []ev) []iline {
	var ls []iline
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
			v := e[k]
			var s string
			switch x := v.(type) {
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

func (m *model) inspector(t *trace) []iline {
	st := stages[m.stage]
	if t == nil {
		return []iline{dim("Nothing sent yet. Write a line in the agent panel and press enter.")}
	}
	if fetched[st] {
		if c := m.insp[t.id+"/"+st]; c != nil {
			return c.lines
		}
		return []iline{dim("loading…")}
	}
	switch st {
	case "agent":
		return []iline{
			head(fmt.Sprintf("POST %s/log → agent prints on %s  (%d B)", config.AgentURL, t.stream, len(t.stdout)+1)),
			lin("plain", t.stdout),
		}
	case "viewer":
		if len(t.reads) == 0 {
			return []iline{dim("Nobody has read this line yet. Esc, then m, s or o.")}
		}
		var ls []iline
		for i := len(t.reads) - 1; i >= 0; i-- {
			r := t.reads[i]
			ls = append(ls, head(fmt.Sprintf("%s  %s  %s", r.at.Local().Format("15:04:05"), r.who, r.url)))
			switch {
			case r.err != "":
				ls = append(ls, lin("denied", fmt.Sprintf("%d %s", r.code, r.err)))
			case len(r.lines) > 0:
				for _, l := range r.lines {
					ls = append(ls, lin("plain", l))
				}
			case r.chunkStatus != "":
				ls = append(ls, lin("denied", fmt.Sprintf("no plaintext: chunk %s (%s)", r.chunkStatus, r.reason)),
					lin("sealed", fmt.Sprintf("ct=%s…  (object %d B)", r.ctPreview, r.objectBytes)))
			default:
				ls = append(ls, dim("chunk not found yet"))
			}
		}
		return ls
	}
	evs := m.derive(t).byStage[st]
	if len(evs) == 0 {
		return []iline{dim("No events from %s for this line yet.", st)}
	}
	return eventLines(evs)
}

// ---- view ----

const compW = 60

func (m *model) View() string {
	if m.w == 0 {
		return "loading…"
	}
	t := m.cur()
	var d derived
	if t != nil {
		d = m.derive(t)
	}
	var b strings.Builder
	headLine := sTitle.Render("Sealed customer logs · demo harness") + sDim.Render("   kind cluster "+config.KubeContext)
	if t != nil {
		headLine += sDim.Render(fmt.Sprintf("   trace %s (%d/%d, [ ] to switch)", t.id, m.sel+1, len(m.traces)))
	}
	b.WriteString(headLine + "\n\n" + m.pipeline(d) + "\n" + m.marker() + "\n" + legend() + "\n")

	lifeH := 8
	midH := max(12, m.h-6-2-(lifeH+2))
	cw := compW
	if m.w < 2*compW {
		cw = m.w / 2
	}
	lp, rp := sPanel, sFocus
	if m.compose {
		lp, rp = sFocus, sPanel
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		lp.Width(cw-2).Height(midH-2).Render(m.composerView(cw-4, midH-2)),
		rp.Width(m.w-cw-2).Height(midH-2).Render(m.inspectorView(t, m.w-cw-4, midH-2))) + "\n")
	b.WriteString(sPanel.Width(m.w-2).Render(m.lifecycle(d, t != nil, lifeH)) + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(zoneColor(m.statusZ)).Render(truncate(m.status, m.w)) + "\n")
	help := "NAVIGATE  ←/→ stage · ↑/↓ scroll · [ ] trace · m/s/o read as member/staff/other · g scan storage · p purge today · x plaintext POST · tab compose · q quit"
	if m.compose {
		help = "COMPOSE  enter send · tab/↑↓ field · ←/→ change level/stream · ctrl+u clear field · esc navigate · ctrl+c quit"
	}
	b.WriteString(sDim.Render(truncate(help, m.w)))
	return b.String()
}

func (m *model) composerView(w, h int) string {
	c := m.comp
	rows := []string{
		sTitle.Foreground(ifc(m.compose, cPlain, cText)).Render("AGENT · write a log line"),
		sDim.Render(truncate("pod identity, set by the sidecar: project "+config.DemoProject+" · agent ag_demo", w)),
		"",
	}
	for i, name := range fieldNames {
		focused := m.compose && c.field == i
		label := sDim.Render(fmt.Sprintf("  %-11s", name))
		if focused {
			label = lipgloss.NewStyle().Foreground(cPlain).Bold(true).Render(fmt.Sprintf("› %-11s", name))
		}
		val := []string{"‹ " + levels[c.level] + " ›", "‹ " + streams[c.stream] + " ›", c.session, c.attrs, c.msg}[i]
		if focused && i >= fSession {
			val += "▌"
		}
		vs := lipgloss.NewStyle().Foreground(ifc(i == fMsg, cPlain, cText))
		for j, ch := range wrap(val, w-13) {
			rows = append(rows, ifs(j == 0, label, strings.Repeat(" ", 13))+vs.Render(ch))
		}
	}
	rows = append(rows, "")
	if rec, err := m.record("t_……"); err != nil {
		rows = append(rows, lipgloss.NewStyle().Foreground(cBad).Render(truncate(err.Error(), w)))
	} else {
		line, _ := json.Marshal(rec)
		rows = append(rows, sDim.Render(streams[c.stream]+" will get:"))
		for _, l := range wrap(string(line), w) {
			rows = append(rows, sDim.Render(l))
		}
	}
	rows = append(rows, "", sDim.Render(ifs(m.compose, "enter sends · esc to navigate", "tab to compose")))
	return strings.Join(rows[:min(len(rows), h)], "\n")
}

func (m *model) inspectorView(t *trace, w, h int) string {
	st := stages[m.stage]
	title := sTitle.Render("INSPECT · "+st) + sDim.Render(map[bool]string{
		true:  "  (read live from the store every 2 s)",
		false: ifs(st == "agent" || st == "viewer", "  (what the harness sent or received)", "  (events this service reported)"),
	}[fetched[st]])
	var rows []string
	for _, l := range m.inspector(t) {
		style := lipgloss.NewStyle().Foreground(cText)
		switch l.kind {
		case "head":
			style = sTitle
		case "plain":
			style = style.Foreground(cPlain)
		case "sealed":
			style = style.Foreground(cSealed)
		case "key":
			style = style.Foreground(cKey)
		case "denied":
			style = style.Foreground(cBad)
		case "dim":
			style = sDim
		}
		for _, wl := range wrap(l.text, w) {
			rows = append(rows, style.Render(wl))
		}
	}
	body := h - 3 // title, blank, footer
	m.scroll = min(m.scroll, max(0, len(rows)-body))
	rows = rows[m.scroll:]
	footer := ""
	if len(rows) > body {
		footer = sDim.Render(fmt.Sprintf("… %d more lines (↓/j to scroll)", len(rows)-body))
		rows = rows[:body]
	} else if m.scroll > 0 {
		footer = sDim.Render("(↑/k to scroll up)")
	}
	return strings.Join(append(append([]string{title, ""}, rows...), footer), "\n")
}

func legend() string {
	l := func(z zone, s string) string {
		return lipgloss.NewStyle().Foreground(zoneColor(z)).Render("■ ") + sDim.Render(s)
	}
	return l(zPlain, "plaintext   ") + l(zSealed, "sealed   ") + l(zKey, "key material   ") + l(zDenied, "denied / destroyed")
}

func (m *model) boxWidth() int { return max(9, (m.w-len(stages)*2)/len(stages)) }

func (m *model) pipeline(d derived) string {
	bw := m.boxWidth()
	var boxes []string
	for i, st := range stages {
		color := cDim
		for _, s := range d.steps {
			if s.stage == st {
				color = zoneColor(s.zone)
			}
		}
		boxes = append(boxes, lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(color).Foreground(color).
			Width(bw-2).Align(lipgloss.Center).Render(truncate(st, bw-2)))
		if i < len(stages)-1 {
			boxes = append(boxes, sDim.Render("→"))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Center, boxes...)
}

// marker points at the box the inspector is showing.
func (m *model) marker() string {
	bw := m.boxWidth()
	pos := max(0, m.stage*(bw+1)+bw/2-4)
	return strings.Repeat(" ", pos) + ifst(m.compose, sDim, sTitle).Render("▲ inspect")
}

func (m *model) lifecycle(d derived, any bool, h int) string {
	if !any {
		return sDim.Render("No line sent yet. The lifecycle of each line you send shows here, step by step.")
	}
	w := m.w - 6
	var rows []string
	for i, s := range d.steps {
		tag := lipgloss.NewStyle().Foreground(zoneColor(s.zone)).Bold(true).Render(fmt.Sprintf("%-9s", zoneTag(s.zone)))
		rows = append(rows, fmt.Sprintf("%02d %s %s %-10s %s", i+1, sDim.Render(s.ts.Local().Format("15:04:05.000")), tag, s.stage, truncate(s.title, w-42)))
		if s.detail != "" {
			rows = append(rows, sDim.Render(strings.Repeat(" ", 39)+truncate(s.detail, w-40)))
		}
	}
	return strings.Join(rows[max(0, len(rows)-h):], "\n")
}

// ---- helpers ----

// wrap hard-wraps s to n runes per line.
func wrap(s string, n int) []string {
	n = max(n, 4)
	var out []string
	for _, para := range strings.Split(s, "\n") {
		r := []rune(para)
		for len(r) > n {
			out = append(out, string(r[:n]))
			r = r[n:]
		}
		out = append(out, string(r))
	}
	return out
}

func truncate(s string, n int) string {
	if n <= 1 {
		return ""
	}
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

func ifn(c bool, a, b int) int {
	if c {
		return a
	}
	return b
}

func ifz(c bool, a, b zone) zone {
	if c {
		return a
	}
	return b
}

func ifc(c bool, a, b lipgloss.Color) lipgloss.Color {
	if c {
		return a
	}
	return b
}

func ifst(c bool, a, b lipgloss.Style) lipgloss.Style {
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
