# Sealed customer logs: prototype

Customer log bodies are sealed at the source with a per-project, per-day key.
Storage only holds ciphertext plus a metadata index. A project member's query
decrypts in the aggregator after keysvc approves the unwrap. Staff and other
projects get ciphertext. Purging a day destroys its key.

Local only. Not production code. Runs on a [kind](https://kind.sigs.k8s.io) cluster.

## Run

Needs Docker, kind, kubectl and Go.

    ./up.sh           # create the kind cluster (once), build + load the image, apply deploy/, wait
    ./bin/tui         # demo harness
    ./down.sh         # delete the cluster and all its data

`up.sh` is safe to rerun after code changes: it rebuilds, reloads and restarts the
app deployments. `SEED=1 ./up.sh` also writes three past days of SDK logs.
`CHATTER=1 ./up.sh` makes the fake agent log on its own. Both are off, so storage
only holds what you send. Every kubectl call pins `--context kind-sealed`, and
`up.sh` restores your current context after creating the cluster.

The TUI is the harness. You play the customer's agent:

- **Compose** (left panel): level, stream, session_id, attrs (`k=v k=v`) and the
  message. Enter POSTs it to the agent pod, which prints it as one JSON line on
  stdout or stderr. The sidecar reads it from a FIFO, chunks per session, seals
  and ships.
- **Inspect** (right panel): for the selected box and line.
  - sidecar, collector, aggregator: the events that service reported, as-is.
  - bucket, clickhouse, keysvc: read live from the stores (the S3 object, the
    index row, the key record and its audit rows), with a check that your
    message text is not in them.
  - agent, viewer: what the harness sent and what each reader got back.
- Esc switches to navigation: `←/→` stage, `↑/↓` scroll, `[ ]` line, `m`/`s`/`o`
  read as project member / operator staff / another project's member, `g` scan raw
  storage for your message, `p` purge today, `x` post plaintext like an old SDK,
  `tab` back to compose.

Other ways in:

    bin/logs --as member --q 4111                # digit needles also match through separators
    bin/logs --as staff
    bin/logs --scan                              # what an attacker with the bucket + ClickHouse sees
    bin/logs --purge $(date -u +%F)
    open 'http://127.0.0.1:18123/play?user=sealed&password=sealed'   # ClickHouse's SQL UI
    kubectl --context kind-sealed -n sealed-logs exec deploy/keysvc -- ls /data/var   # SQLite key store
    SEALED_LIVE=1 go test ./cmd/tui -v           # drives the harness end to end

## Layout

Namespace `sealed-logs`. Manifests are plain YAML in `deploy/` (kustomize).
Host ports map to NodePorts through `deploy/kind.yaml`:

| Host port | Service |
|---|---|
| 7101 | keysvc |
| 7102 | collector |
| 7103 | aggregator |
| 7104 | agent pod, harness `POST /log` |
| 18123 | ClickHouse HTTP |
| 19100 | object store (S3 API) |

| Workload | Role | Stand-in for |
|---|---|---|
| `agent` pod: `agent` container | Customer code (`producer fakeagent`). Its entrypoint redirects stdout/stderr into FIFOs on an in-memory emptyDir, so the container runtime never writes its log text to node disk | customer agent container |
| `agent` pod: `log-sidecar` container | Reads the FIFOs, seals chunks (zstd + HPKE X25519/AES-256-GCM), ships | a hosting platform's log-shipping sidecar |
| `collector` | Accepts only `{meta, sealed}`, stores the object, writes a metadata index row | log ingest service |
| `keysvc` | Day key pairs per project, wrapped by OpenBao Transit (derived per project), signed public keys, member-only unwrap, purge, retention, revocation feed, audit. SQLite on a PVC, one replica | key service |
| `aggregator` | Index query → fetch chunks → unwrap with the caller's token → decrypt/filter in memory; per-caller key cache evicted by the revocation feed | log query service |
| `clickhouse` | `sealed.log_chunks`: one metadata row per chunk, no text | ClickHouse |
| `objectstore` | SeaweedFS, S3 API: sealed chunk objects | any S3-compatible object store |
| `openbao` | Master key (Transit) behind the `KeyWrapper` interface. Dev mode, in memory | any KMS |

Pods labelled `sealed-logs/events=true` print JSON lifecycle events on stdout
(tagged `"ev":"sealedlogs/v1"`, never log text). The TUI follows them with
`kubectl logs -f -l sealed-logs/events=true`.

## Known gaps

- Shared HMAC tokens stand in for project tokens, workload identity (projected
  service-account tokens) and SSO.
- keysvc runs one replica on SQLite; production would use CockroachDB.
- OpenBao runs in dev mode: if its pod restarts, the Transit master key is gone and
  every stored chunk becomes unreadable. Recreate with `./down.sh && ./up.sh`.
- No Kafka/router, no TLS between services, no NetworkPolicy, single region, no HA.
- Browser-held (passkey) keys and customer KMS are not built.
