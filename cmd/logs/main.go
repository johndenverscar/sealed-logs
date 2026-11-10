// logs is the viewer: it queries the aggregator as one of the demo identities.
//
//	logs --as member|staff|other [--q 4111] [--since 1h] [--session ses_x] [--level warn]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
	"sealedlogs/internal/scan"
)

func main() {
	as := flag.String("as", "member", "member | staff | other")
	project := flag.String("project", config.DemoProject, "project to query")
	q := flag.String("q", "", "text search (all-digit needles also match through separators)")
	since := flag.String("since", "24h", "lookback")
	session := flag.String("session", "", "session id")
	level := flag.String("level", "", "minimum level")
	doScan := flag.Bool("scan", false, "scan raw storage for planted secrets instead of querying")
	purge := flag.String("purge", "", "destroy the project's keys for a UTC day (YYYY-MM-DD) as a member")
	flag.Parse()

	if *doScan {
		r, err := scan.Run(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(r)
		return
	}
	if *purge != "" {
		body, _ := json.Marshal(map[string]string{"project": *project, "from": *purge, "to": *purge})
		req, _ := http.NewRequest(http.MethodPost, config.KeysvcURL+"/purge", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+auth.DemoToken(*as))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		fmt.Printf("%d %s", resp.StatusCode, b)
		return
	}

	v := url.Values{"project": {*project}, "since": {*since}, "q": {*q}, "session": {*session}, "level": {*level}}
	req, _ := http.NewRequest(http.MethodGet, config.AggregatorURL+"/logs?"+v.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+auth.DemoToken(*as))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Caller map[string]string `json:"caller"`
		Chunks []struct {
			ChunkID   string `json:"chunk_id"`
			KeyID     string `json:"key_id"`
			Status    string `json:"status"`
			Reason    string `json:"reason"`
			CTPreview string `json:"ct_preview"`
		} `json:"chunks"`
		Lines []struct {
			TS        time.Time `json:"ts"`
			Level     string    `json:"level"`
			Msg       string    `json:"msg"`
			SessionID string    `json:"session_id"`
		} `json:"lines"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error != "" {
		fmt.Fprintln(os.Stderr, "error:", out.Error)
		os.Exit(1)
	}
	counts := map[string]int{}
	for _, c := range out.Chunks {
		counts[c.Status]++
	}
	fmt.Printf("as %s (%s, project %q): %d chunks %v\n", out.Caller["sub"], out.Caller["role"], out.Caller["project"], len(out.Chunks), counts)
	for _, c := range out.Chunks {
		if c.Status != "decrypted" {
			fmt.Printf("  %-14s %-28s %-10s %s  ct=%s…\n", c.ChunkID, c.KeyID, c.Status, c.Reason, c.CTPreview)
		}
	}
	for _, l := range out.Lines {
		fmt.Printf("%s %-5s %-10s %s\n", l.TS.Local().Format("Jan 02 15:04:05"), l.Level, l.SessionID, l.Msg)
	}
}
