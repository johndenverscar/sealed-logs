// producer plays every log source in the prototype:
//
//	producer sidecar   reads the agent container's stdout/stderr from FIFOs on a
//	                   shared emptyDir, seals chunks and ships them
//	producer fakeagent a "customer agent": prints whatever the harness POSTs to
//	                   /log, plus optional chatter and planted secrets
//	producer sdk       structured logs sealed in-process, like a self-hosted agent
//	producer plaintext a misbehaving client that posts unsealed logs
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
	"sealedlogs/internal/envelope"
	"sealedlogs/internal/events"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: producer sidecar|fakeagent|sdk|plaintext [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "sidecar":
		sidecar(args)
	case "fakeagent":
		fakeAgent(args)
	case "sdk":
		sdk(args)
	case "plaintext":
		plaintext(args)
	default:
		log.Fatalf("unknown mode %q", cmd)
	}
}

// ---- shipping ----

type shipper struct {
	project, agent, session, source string
	daysAgo                         int
	tok                             string
	http                            *http.Client

	mu      sync.Mutex
	signPub ed25519.PublicKey
	keys    map[string]pubKey
}

type pubKey struct {
	id      string
	pub     []byte
	fetched time.Time
}

func newShipper(project, agent, session, source string, daysAgo int) *shipper {
	return &shipper{
		project: project, agent: agent, session: session, source: source, daysAgo: daysAgo,
		tok:  auth.Mint("w_"+source+"_"+agent, project, auth.RoleProducer, 24*time.Hour),
		http: &http.Client{Timeout: 5 * time.Second}, keys: map[string]pubKey{},
	}
}

func (s *shipper) getJSON(u string, out any) error {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+s.tok)
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %d %s", u, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, out)
}

// pubkey returns the day's public key, verified against keysvc's signing key.
// The short cache picks up a new key generation soon after a purge.
func (s *shipper) pubkey(day string) (pubKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[day]; ok && time.Since(k.fetched) < 5*time.Second {
		return k, nil
	}
	if s.signPub == nil {
		var sk struct{ Pub []byte }
		if err := s.getJSON(config.KeysvcURL+"/signing-key", &sk); err != nil {
			return pubKey{}, err
		}
		s.signPub = sk.Pub
	}
	var out struct {
		KeyID string `json:"key_id"`
		Pub   []byte `json:"pub"`
		Sig   []byte `json:"sig"`
	}
	u := fmt.Sprintf("%s/pubkey?project=%s&day=%s", config.KeysvcURL, url.QueryEscape(s.project), day)
	if err := s.getJSON(u, &out); err != nil {
		return pubKey{}, err
	}
	if !ed25519.Verify(s.signPub, envelope.SignedMessage(out.KeyID, out.Pub), out.Sig) {
		return pubKey{}, errors.New("public key signature does not verify")
	}
	k := pubKey{id: out.KeyID, pub: out.Pub, fetched: time.Now()}
	s.keys[day] = k
	events.Emit(s.source, "pubkey", map[string]any{
		"key_id": k.id, "pub_hex": events.Preview(k.pub, 32), "signature": "ed25519 verified against keysvc /signing-key",
	})
	return k, nil
}

func (s *shipper) ship(session string, lines []envelope.Line, traces []string) error {
	if len(lines) == 0 {
		return nil
	}
	if s.daysAgo > 0 {
		for i := range lines {
			lines[i].TS = lines[i].TS.AddDate(0, 0, -s.daysAgo)
		}
	}
	day := lines[0].TS.UTC().Format("2006-01-02")
	k, err := s.pubkey(day)
	if err != nil {
		return err
	}
	m := envelope.Meta{
		Project: s.project, ChunkID: "c_" + randHex(5), KeyID: k.id, SessionID: session, AgentID: s.agent,
		Source: s.source, TSMin: lines[0].TS, TSMax: lines[len(lines)-1].TS, Lines: uint32(len(lines)),
		Levels: map[string]uint32{},
	}
	for _, l := range lines {
		m.Levels[l.Level]++
	}
	sealed, ptBytes, err := envelope.Seal(k.pub, m, lines)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(envelope.Chunk{Meta: m, Sealed: sealed})
	// meta is the plaintext index and carries no log text; enc/ct are ciphertext.
	events.Emit(s.source, "sealed", map[string]any{
		"chunk_id": m.ChunkID, "key_id": k.id, "lines": len(lines), "traces": traces,
		"pt_bytes": ptBytes, "ct_bytes": len(sealed.CT), "enc_bytes": len(sealed.Enc), "post_bytes": len(body),
		"enc_preview": events.Preview(sealed.Enc, 8), "ct_preview": events.Preview(sealed.CT, 16),
		"meta": m, "sub": "w_" + s.source + "_" + s.agent,
	})

	req, _ := http.NewRequest(http.MethodPost, config.CollectorURL+"/chunks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+s.tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("collector %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// ---- sidecar ----

var (
	levelRe = regexp.MustCompile(`^\[(DEBUG|INFO|WARN|ERROR)\]\s*`)
	traceRe = regexp.MustCompile(`trace=(t_[0-9a-f]+)`)
)

type rawLine struct {
	ts     time.Time
	stream string
	text   string
}

func sidecar(args []string) {
	fs := flag.NewFlagSet("sidecar", flag.ExitOnError)
	project := fs.String("project", config.DemoProject, "project id")
	agent := fs.String("agent", "ag_demo", "agent id")
	session := fs.String("session", "ses_demo", "session id")
	flush := fs.Duration("flush", 2*time.Second, "max time a line waits before its chunk is sealed")
	maxLines := fs.Int("max-lines", 64, "max lines per chunk")
	stdoutPath := fs.String("stdout", "/logs/stdout.pipe", "FIFO the agent's stdout is redirected to")
	stderrPath := fs.String("stderr", "/logs/stderr.pipe", "FIFO the agent's stderr is redirected to")
	_ = fs.Parse(args)

	sh := newShipper(*project, *agent, *session, "sidecar", 0)
	ch := make(chan rawLine, 1024)
	// Opening a FIFO blocks until the agent opens its end. EOF means the agent
	// container exited; reopen and wait for its restart.
	read := func(path, stream string) {
		for {
			f, err := os.Open(path)
			if err != nil {
				log.Printf("sidecar: open %s: %v", path, err)
				time.Sleep(time.Second)
				continue
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				ch <- rawLine{ts: time.Now().UTC(), stream: stream, text: sc.Text()}
			}
			f.Close()
		}
	}
	go read(*stdoutPath, "stdout")
	go read(*stderrPath, "stderr")
	log.Printf("sidecar: reading %s and %s", *stdoutPath, *stderrPath)

	var buf []envelope.Line
	var traces []string
	bufSession := *session
	tick := time.NewTicker(*flush)
	send := func() {
		if len(buf) == 0 {
			return
		}
		if err := sh.ship(bufSession, buf, traces); err != nil {
			log.Printf("sidecar: ship failed: %v", err)
			events.Emit("sidecar", "ship_failed", map[string]any{"error": err.Error(), "traces": traces})
		}
		buf, traces = nil, nil
	}
	for {
		select {
		case l := <-ch:
			line, sess, trace := parseLine(l)
			if sess == "" {
				sess = *session
			}
			// One chunk per session, so a session's logs can be found and purged together.
			if len(buf) > 0 && sess != bufSession {
				send()
			}
			bufSession = sess
			buf = append(buf, line)
			// The sidecar sees plaintext anyway; for the observer it reports only the trace marker.
			if trace != "" {
				traces = append(traces, trace)
				events.Emit("sidecar", "buffered", map[string]any{
					"trace": trace, "stream": l.stream, "pending": len(buf), "line_bytes": len(l.text), "session_id": sess,
				})
			}
			if len(buf) >= *maxLines {
				send()
			}
		case <-tick.C:
			send()
		}
	}
}

// jsonLine is what a structured logger (Python's json formatter, pino, zap) prints.
type jsonLine struct {
	TS        time.Time         `json:"ts"`
	Level     string            `json:"level"`
	Msg       string            `json:"msg"`
	SessionID string            `json:"session_id"`
	Attrs     map[string]string `json:"attrs"`
}

// parseLine turns one stdout/stderr line into a log line. JSON lines keep their
// level, session and attributes; anything else is plain text with an optional
// [LEVEL] prefix.
func parseLine(l rawLine) (envelope.Line, string, string) {
	var j jsonLine
	if strings.HasPrefix(l.text, "{") && json.Unmarshal([]byte(l.text), &j) == nil && j.Msg != "" {
		level := strings.ToLower(j.Level)
		if level == "" {
			level = "info"
		}
		ts := l.ts
		if !j.TS.IsZero() {
			ts = j.TS.UTC()
		}
		return envelope.Line{TS: ts, Level: level, Msg: j.Msg, Stream: l.stream, Attrs: j.Attrs}, j.SessionID, j.Attrs["trace"]
	}
	level, text := "info", l.text
	if m := levelRe.FindStringSubmatch(text); m != nil {
		level, text = strings.ToLower(m[1]), text[len(m[0]):]
	} else if l.stream == "stderr" {
		level = "error"
	}
	trace := ""
	if m := traceRe.FindStringSubmatch(text); m != nil {
		trace = m[1]
	}
	return envelope.Line{TS: l.ts, Level: level, Msg: text, Stream: l.stream}, "", trace
}

// ---- fake agent ----

var chatter = []string{
	"[INFO] agent session started session=ses_demo caller=caller_1",
	"[DEBUG] stt partial transcript received (412ms)",
	"[INFO] llm response streamed in 640ms tokens=118",
	"[DEBUG] tts synthesized 2.4s audio voice=default",
	"[INFO] tool call get_order_status order_id=88231",
	"[WARN] llm latency above budget: 1.9s",
	"[INFO] user turn ended, endpointing after 520ms silence",
	"[DEBUG] vad speech start",
}

var secrets = [][]string{
	{"[INFO] payment tool result: card 4111 1111 1111 1111 exp 12/28 cvv 123"},
	{"[DEBUG] user said: my social is 123", "[DEBUG] user said: 45 6789"},
	{"[WARN] retrying charge for 4🙂1🙂1🙂1 1111 1111 1111"},
	{"[INFO] caller dob=1984-03-07 address=12 Elm St, Springfield"},
}

func fakeAgent(args []string) {
	fs := flag.NewFlagSet("fakeagent", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "address for the harness's POST /log")
	rate := fs.Duration("rate", 1500*time.Millisecond, "time between chatter lines")
	chat := fs.Bool("chatter", false, "print background chatter and planted secrets")
	_ = fs.Parse(args)

	// Everything this process prints is the customer's log output, so the HTTP
	// server must not log anything of its own.
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("POST /log", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Stream, Text string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || in.Text == "" || strings.Contains(in.Text, "\n") {
			http.Error(w, "want {stream, text} with one line of text", http.StatusBadRequest)
			return
		}
		mu.Lock()
		if in.Stream == "stderr" {
			fmt.Fprintln(os.Stderr, in.Text)
		} else {
			fmt.Println(in.Text)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.ListenAndServe() }()

	if !*chat {
		select {}
	}
	i := 0
	for range time.Tick(*rate) {
		i++
		if i%12 == 0 {
			for _, l := range secrets[mrand.IntN(len(secrets))] {
				fmt.Println(l)
			}
			continue
		}
		if i%17 == 0 {
			fmt.Fprintln(os.Stderr, "Traceback: ConnectionResetError: peer closed the stream")
			continue
		}
		fmt.Println(chatter[mrand.IntN(len(chatter))])
	}
}

// ---- sdk ----

func sdk(args []string) {
	fs := flag.NewFlagSet("sdk", flag.ExitOnError)
	project := fs.String("project", config.DemoProject, "project id")
	agent := fs.String("agent", "ag_selfhosted", "agent id")
	session := fs.String("session", "", "session id (random if empty)")
	n := fs.Int("n", 40, "lines to emit")
	daysAgo := fs.Int("days-ago", 0, "backdate the logs (keysvc needs DEMO_ALLOW_PAST=1)")
	_ = fs.Parse(args)
	if *session == "" {
		*session = "ses_" + randHex(3)
	}

	sh := newShipper(*project, *agent, *session, "sdk", *daysAgo)
	var buf []envelope.Line
	for i := 0; i < *n; i++ {
		text := chatter[mrand.IntN(len(chatter))]
		if i%10 == 9 {
			text = secrets[0][0]
		}
		level := "info"
		if m := levelRe.FindStringSubmatch(text); m != nil {
			level, text = strings.ToLower(m[1]), text[len(m[0]):]
		}
		buf = append(buf, envelope.Line{TS: time.Now().UTC().Add(time.Duration(i) * time.Second), Level: level, Msg: text,
			Attrs: map[string]string{"sdk": "python-1.3.0"}})
		if len(buf) == 10 {
			must(sh.ship(sh.session, buf, nil))
			buf = nil
		}
	}
	must(sh.ship(sh.session, buf, nil))
	log.Printf("sdk: shipped %d lines for %s (%d days ago)", *n, *session, *daysAgo)
}

// ---- plaintext ----

func plaintext(args []string) {
	fs := flag.NewFlagSet("plaintext", flag.ExitOnError)
	project := fs.String("project", config.DemoProject, "project id")
	_ = fs.Parse(args)

	body, _ := json.Marshal(map[string]any{
		"meta":  map[string]any{"project": *project, "chunk_id": "c_plain"},
		"lines": []map[string]string{{"level": "info", "msg": "card 4111 1111 1111 1111"}},
	})
	req, _ := http.NewRequest(http.MethodPost, config.CollectorURL+"/chunks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth.Mint("w_legacy_sdk", *project, auth.RoleProducer, time.Hour))
	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Printf("%d %s", resp.StatusCode, b)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
