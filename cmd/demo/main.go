// demo serves the web demo on http://127.0.0.1:7100. It has two views:
//
//   - Pipeline: you play the customer's agent. Write a log line and the page POSTs
//     it to the agent pod, which prints it on stdout or stderr. Every service
//     reports what it received and produced as JSON events on its own stdout, and
//     this server follows them with kubectl logs. The bucket, ClickHouse and keysvc
//     panels are read live from the stores. Nothing shown is asserted by the demo.
//   - Logs: the product's log viewer, as the customer would use it. It queries the
//     aggregator as whichever demo identity you pick.
//
// The page talks only to this server; the server talks to the cluster.
package main

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"slices"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
)

//go:embed static
var static embed.FS

func main() {
	d := newDemo()
	addr := config.Env("DEMO_ADDR", "127.0.0.1:7100")
	log.Printf("demo on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, d.routes()))
}

func (d *Demo) routes() *http.ServeMux {
	sub, _ := fs.Sub(static, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(sub))
	mux.HandleFunc("GET /api/state", d.state)
	mux.HandleFunc("POST /api/send", d.send)
	mux.HandleFunc("GET /api/inspect", d.inspect)
	mux.HandleFunc("POST /api/read", d.read)
	mux.HandleFunc("POST /api/scan", d.scan)
	mux.HandleFunc("POST /api/purge", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, PurgeToday()) })
	mux.HandleFunc("POST /api/plaintext", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, SendPlaintext()) })
	mux.HandleFunc("GET /api/logs", logs)
	return mux
}

type traceView struct {
	*Trace
	ChunkID string          `json:"chunk_id"`
	KeyID   string          `json:"key_id"`
	Steps   []Step          `json:"steps"`
	Stages  map[string]Zone `json:"stages"` // the zone of each stage's latest step
}

func (d *Demo) state(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	traces := slices.Clone(d.traces)
	d.mu.Unlock()
	views := []traceView{}
	for _, t := range traces {
		dv := d.Derive(t)
		v := traceView{Trace: t, ChunkID: dv.ChunkID, KeyID: dv.KeyID, Steps: dv.Steps, Stages: map[string]Zone{}}
		for _, s := range dv.Steps {
			v.Stages[s.Stage] = s.Zone
		}
		views = append(views, v)
	}
	writeJSON(w, map[string]any{
		"project": config.DemoProject, "kube_context": config.KubeContext,
		"stages": stages, "viewers": viewers, "traces": views,
	})
}

func (d *Demo) send(w http.ResponseWriter, r *http.Request) {
	var c Compose
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeJSON(w, Result{Status: "bad request: " + err.Error(), Zone: zDenied})
		return
	}
	writeJSON(w, d.Send(c))
}

func (d *Demo) inspect(w http.ResponseWriter, r *http.Request) {
	t := d.trace(r.URL.Query().Get("trace"))
	st := r.URL.Query().Get("stage")
	if t == nil || !slices.Contains(stages, st) {
		writeJSON(w, map[string]any{"lines": []Line{dim("Send a line first.")}})
		return
	}
	source := "events this service reported"
	switch {
	case fetched[st]:
		source = "read live from the store"
	case st == "agent" || st == "viewer":
		source = "what the demo sent or received"
	}
	writeJSON(w, map[string]any{"source": source, "lines": d.Inspect(t, st)})
}

type actionReq struct {
	Trace string `json:"trace"`
	As    string `json:"as"`
}

func (d *Demo) read(w http.ResponseWriter, r *http.Request) {
	var a actionReq
	_ = json.NewDecoder(r.Body).Decode(&a)
	t := d.trace(a.Trace)
	if t == nil {
		writeJSON(w, Result{Status: "send a line first", Zone: zInfo})
		return
	}
	writeJSON(w, d.ReadAs(t, a.As))
}

func (d *Demo) scan(w http.ResponseWriter, r *http.Request) {
	var a actionReq
	_ = json.NewDecoder(r.Body).Decode(&a)
	writeJSON(w, d.Scan(d.trace(a.Trace)))
}

// logs is the Logs view's backend: it queries the aggregator as a demo identity
// and passes the response through unchanged.
func logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	as := q.Get("as")
	if _, ok := viewers[as]; !ok {
		as = "member"
	}
	v := url.Values{"project": {config.DemoProject}, "since": {q.Get("since")}, "q": {q.Get("q")},
		"session": {q.Get("session")}, "limit": {"500"}}
	req, _ := http.NewRequest(http.MethodGet, config.AggregatorURL+"/logs?"+v.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+auth.DemoToken(as))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		writeJSON(w, map[string]string{"error": "aggregator: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func writeJSON(w http.ResponseWriter, v any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	_ = json.NewEncoder(w).Encode(v)
}
