// collector accepts sealed chunks from producers, stores the object, and writes a
// metadata-only index row to ClickHouse. It never holds a key and never decrypts.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/config"
	"sealedlogs/internal/envelope"
	"sealedlogs/internal/events"
)

const schema = `CREATE TABLE IF NOT EXISTS sealed.log_chunks (
  project LowCardinality(String),
  chunk_id String,
  key_id String,
  day Date,
  ts_min DateTime64(3, 'UTC'),
  ts_max DateTime64(3, 'UTC'),
  session_id String,
  agent_id String,
  source LowCardinality(String),
  lines UInt32,
  n_debug UInt32, n_info UInt32, n_warn UInt32, n_error UInt32,
  object_key String,
  object_bytes UInt32,
  ingested_at DateTime64(3, 'UTC')
) ENGINE = MergeTree ORDER BY (project, ts_min)`

type server struct {
	ch    driver.Conn
	store *minio.Client
}

func main() {
	ctx := context.Background()
	ch, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{config.CHAddr},
		Auth: clickhouse.Auth{Database: "default", Username: config.CHUser, Password: config.CHPass},
	})
	must(err)
	must(ch.Exec(ctx, "CREATE DATABASE IF NOT EXISTS sealed"))
	must(ch.Exec(ctx, schema))

	mc, err := minio.New(config.MinioEndpoint, &minio.Options{Creds: credentials.NewStaticV4(config.MinioUser, config.MinioPass, "")})
	must(err)
	if ok, err := mc.BucketExists(ctx, config.Bucket); err == nil && !ok {
		must(mc.MakeBucket(ctx, config.Bucket, minio.MakeBucketOptions{}))
	} else {
		must(err)
	}

	// The object store's first write can take several seconds while it allocates a
	// volume. Pay that before reporting ready, not inside a producer's request.
	must(warmUp(ctx, mc))

	s := &server{ch: ch, store: mc}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("POST /chunks", s.chunks)

	addr := config.Env("COLLECTOR_ADDR", "127.0.0.1:7102")
	log.Printf("collector on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (s *server) chunks(w http.ResponseWriter, r *http.Request) {
	c, _, err := auth.FromRequest(r)
	if err != nil || c.Role != auth.RoleProducer {
		httpErr(w, 403, "producer token required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		httpErr(w, 400, "read body")
		return
	}

	ch, reason := validate(c, body)
	if reason != "" {
		s.reject(w, c.Project, reason)
		return
	}
	m := ch.Meta
	events.Emit("collector", "accepted", map[string]any{
		"chunk_id": m.ChunkID, "sub": c.Subject, "bytes": len(body), "key_id": m.KeyID,
		"checks": []string{"body has only meta and sealed", "token project = meta.project", "sealed envelope v1 shape", "key_id belongs to project"},
	})
	objectKey := fmt.Sprintf("%s/%s/%s.chunk", m.Project, m.TSMin.UTC().Format("2006-01-02"), m.ChunkID)
	_, err = s.store.PutObject(r.Context(), config.Bucket, objectKey, bytes.NewReader(body), int64(len(body)),
		minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		httpErr(w, 502, "object store: "+err.Error())
		return
	}
	events.Emit("collector", "stored", map[string]any{
		"chunk_id": m.ChunkID, "object_key": config.Bucket + "/" + objectKey, "bytes": len(body), "sub": c.Subject,
	})

	batch, err := s.ch.PrepareBatch(r.Context(), "INSERT INTO sealed.log_chunks")
	if err == nil {
		err = batch.Append(m.Project, m.ChunkID, m.KeyID, m.TSMin.UTC(), m.TSMin.UTC(), m.TSMax.UTC(),
			m.SessionID, m.AgentID, m.Source, m.Lines,
			m.Levels["debug"], m.Levels["info"], m.Levels["warn"], m.Levels["error"],
			objectKey, uint32(len(body)), time.Now().UTC())
	}
	if err == nil {
		err = batch.Send()
	}
	if err != nil {
		httpErr(w, 502, "clickhouse: "+err.Error())
		return
	}
	events.Emit("collector", "indexed", map[string]any{
		"chunk_id": m.ChunkID, "key_id": m.KeyID, "lines": m.Lines, "levels": m.Levels, "session_id": m.SessionID,
	})
	writeJSON(w, 201, map[string]any{"object_key": objectKey})
}

func warmUp(ctx context.Context, mc *minio.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	const key = "_warmup"
	if _, err := mc.PutObject(ctx, config.Bucket, key, bytes.NewReader([]byte("ok")), 2, minio.PutObjectOptions{}); err != nil {
		return err
	}
	return mc.RemoveObject(ctx, config.Bucket, key, minio.RemoveObjectOptions{})
}

// validate returns the chunk, or why it is refused. The collector cannot decrypt,
// so it checks shape and ownership only: the body is exactly {meta, sealed}, the
// token's project owns the chunk, and the key ID belongs to that project.
func validate(c *auth.Claims, body []byte) (envelope.Chunk, string) {
	var ch envelope.Chunk
	if reason := unsealedReason(body); reason != "" {
		return ch, reason
	}
	if err := json.Unmarshal(body, &ch); err != nil {
		return ch, "malformed chunk"
	}
	m, sl := ch.Meta, ch.Sealed
	switch {
	case m.Project != c.Project:
		return ch, "chunk project does not match token"
	case sl.V != envelope.Version || len(sl.Enc) != 32 || len(sl.CT) < 16:
		return ch, "not a valid sealed envelope"
	case sl.KeyID != m.KeyID || !strings.HasPrefix(m.KeyID, m.Project+"/"):
		return ch, "key_id does not belong to this project"
	}
	return ch, ""
}

// unsealedReason rejects anything that is not exactly {meta, sealed}. A producer
// that sends log text in any other field is refused before it touches storage.
func unsealedReason(body []byte) string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return "body is not JSON"
	}
	if _, ok := top["sealed"]; !ok {
		return "no sealed envelope: plaintext logs are refused"
	}
	for k := range top {
		if k != "meta" && k != "sealed" {
			return fmt.Sprintf("unexpected field %q: plaintext logs are refused", k)
		}
	}
	return ""
}

func (s *server) reject(w http.ResponseWriter, project, reason string) {
	events.Emit("collector", "rejected", map[string]any{"project": project, "reason": reason})
	httpErr(w, 422, reason)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
