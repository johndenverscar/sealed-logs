// demo serves the web demo on http://127.0.0.1:7100. It has two views:
//
//   - Pipeline: you play the customer's agent. Write a log line and the page POSTs
//     it to the agent pod, which prints it on stdout or stderr. Every service
//     reports what it received and produced as JSON events on its own stdout, and
//     this server follows them with kubectl logs. The bucket, ClickHouse and keysvc
//     panels are read live from the stores. Nothing shown is asserted by the demo.
//   - Logs: the product's log viewer, as the customer would use it. It queries
//     and live-tails the aggregator as whichever demo identity you pick, and
//     shows support access requests to staff and to project members.
//
// The page talks only to this server; the server talks to the cluster.
package main

import (
	"bytes"
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
	mux.HandleFunc("GET /api/tail", tail)
	mux.HandleFunc("GET /api/grants", grants)
	mux.HandleFunc("POST /api/grants", requestGrant)
	mux.HandleFunc("POST /api/grants/{id}/{action}", decideGrant)
	mux.HandleFunc("GET /api/access-log", accessLog)
	mux.HandleFunc("GET /api/byok", byokState)
	mux.HandleFunc("POST /api/byok/enable", enableBYOK)
	mux.HandleFunc("POST /api/byok/revoke", customerDecrypt(false))
	mux.HandleFunc("POST /api/byok/restore", customerDecrypt(true))
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

// tail proxies the aggregator's live tail (server-sent events) as a demo identity.
func tail(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v := url.Values{"project": {config.DemoProject}, "q": {q.Get("q")}, "session": {q.Get("session")},
		"level": {q.Get("level")}, "after": {q.Get("after")}}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, config.AggregatorURL+"/tail?"+v.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+auth.DemoToken(viewer(q.Get("as"))))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "aggregator: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func viewer(as string) string {
	if _, ok := viewers[as]; ok {
		return as
	}
	return "member"
}

// keysvc calls keysvc as a demo identity and passes the answer through.
func keysvc(w http.ResponseWriter, method, path, as string, body io.Reader) {
	req, _ := http.NewRequest(method, config.KeysvcURL+path, body)
	req.Header.Set("Authorization", "Bearer "+auth.DemoToken(as))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		writeJSON(w, map[string]string{"error": "keysvc: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// grants lists the support access grants the chosen identity can see.
func grants(w http.ResponseWriter, r *http.Request) {
	keysvc(w, http.MethodGet, "/grants?project="+url.QueryEscape(config.DemoProject), viewer(r.URL.Query().Get("as")), nil)
}

// requestGrant is operator staff asking the demo project for temporary access.
func requestGrant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason  string `json:"reason"`
		Minutes int    `json:"minutes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	b, _ := json.Marshal(map[string]any{"project": config.DemoProject, "reason": req.Reason, "minutes": req.Minutes})
	keysvc(w, http.MethodPost, "/grants", "staff", bytes.NewReader(b))
}

// decideGrant approves, denies or ends a grant as the chosen identity.
func decideGrant(w http.ResponseWriter, r *http.Request) {
	keysvc(w, http.MethodPost, "/grants/"+url.PathEscape(r.PathValue("id"))+"/"+url.PathEscape(r.PathValue("action")),
		viewer(r.URL.Query().Get("as")), nil)
}

func writeJSON(w http.ResponseWriter, v any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	_ = json.NewEncoder(w).Encode(v)
}
