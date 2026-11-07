# Design

This is how sealed logs work, why each piece exists, and what the design does and
does not protect against. Each idea links to the code that implements it.

- [The problem](#the-problem)
- [Core ideas](#core-ideas)
- [Threat model](#threat-model)
- [Trade-offs](#trade-offs)
- [What a production version needs](#what-a-production-version-needs)
- [Further reading](#further-reading)

## The problem

A platform that runs customer code collects that code's logs and shows them back
in a log viewer. Customer logs contain whatever the customer's code printed:
card numbers, transcripts, API keys, health data. The usual pipeline stores
those lines in plaintext, which means:

- anyone who gets the bucket or the log database reads every customer's logs;
- every operator with database access can read them, so the customer has to
  trust a policy rather than a mechanism;
- deleting a customer's data means finding and rewriting every copy, including
  backups and replicas.

The goal: the operator stores and indexes the logs, but only the customer's own
project members can read them, and deleting a key deletes the data.

## Core ideas

### 1. Seal at the source with a public key

The producer (a sidecar next to the customer's container, or an SDK inside it)
encrypts each chunk of log lines before it leaves the pod. It encrypts to the
project's **public** key, so the producer holds no secret that could decrypt
anything, including its own earlier output.

The scheme is [HPKE](https://www.rfc-editor.org/rfc/rfc9180) (RFC 9180) with
X25519, HKDF-SHA256 and AES-256-GCM. HPKE generates a fresh ephemeral key for
every seal, so two identical chunks never produce the same ciphertext.

→ `Seal` and `Open` in [`internal/envelope/envelope.go`](../internal/envelope/envelope.go)

### 2. Compress, then encrypt

Lines are serialised as JSON Lines and compressed with zstd before encryption,
because ciphertext does not compress. One HPKE seal covers one chunk (up to 64
lines, or 2 seconds of output, per session), so the public-key cost is paid
once per chunk rather than once per line.

→ the sidecar's flush loop in [`cmd/producer/main.go`](../cmd/producer/main.go)

### 3. Plaintext metadata, authenticated

Storage needs something to index. Each chunk carries a small metadata record:
project, session, agent, time range, line count and a count per log level. It
never carries log text.

The metadata is plaintext, but it is bound to the ciphertext as AEAD
*additional authenticated data*. If anyone changes a field (moves the chunk to
another project, shifts its timestamps, relabels its session), decryption
fails. Storage can read the index; it cannot lie with it.

→ `aad` in [`internal/envelope/envelope.go`](../internal/envelope/envelope.go),
tested by `TestMetadataIsBound`

### 4. Envelope encryption: one key pair per project per day

keysvc issues a key pair per project per UTC day (`p_demo/2026-11-07/g1`). The
private key is never stored in the clear: keysvc wraps it with a master key held
in a KMS (OpenBao Transit here) and stores only the wrapped blob.

The master key is *derived* per project (Transit's `derived` mode, with the
project ID as context), so a wrapped blob for one project does not unwrap under
another project's context.

keysvc signs every public key with an Ed25519 key, and producers verify the
signature before sealing, so a tampered `/pubkey` response cannot make a
producer encrypt to an attacker's key.

→ [`cmd/keysvc/main.go`](../cmd/keysvc/main.go),
[`internal/wrap/wrap.go`](../internal/wrap/wrap.go)

### 5. The unwrap policy is the whole access model

Only one code path turns a wrapped key back into a private key: keysvc's
`/unwrap`. It returns the key if and only if the caller's token has role
`member` and the token's project matches the key's project. Staff, producers
and other projects' members are refused. Every decision, allowed or denied, is
written to an audit table.

→ `unwrap` in [`cmd/keysvc/main.go`](../cmd/keysvc/main.go), tested by
`TestUnwrapPolicy`

### 6. Decrypt at query time, with the caller's identity

The aggregator answers log queries. It has no standing access to any key. For
each query it:

1. narrows the chunks with the metadata index in ClickHouse (project, time
   range, session, "has errors");
2. fetches those sealed objects from the bucket;
3. asks keysvc to unwrap each day key **with the caller's own token**;
4. decrypts and filters the lines in memory, then discards them.

Unwrapped keys are cached per caller (caller + key ID) for 5 minutes, so one
person's access never serves another's query.

Search (`--q 4111`) runs after decryption, on plaintext. That is why it can find
`4-1-1-1` or `4🙂1🙂1🙂1` when you search for `4111`: no index ever saw the text.

→ [`cmd/aggregator/main.go`](../cmd/aggregator/main.go)

### 7. Delete the key, not the data (crypto-shredding)

Purging a day destroys that day's wrapped private keys. The ciphertext stays in
the bucket and is now permanently unreadable. Nothing has to find and rewrite
every copy: backups and replicas of the bucket are shredded at the same moment.

Two details make that true in practice:

- **Generations.** After a mid-day purge the next `/pubkey` call issues
  generation 2 (`…/g2`), so new logs go to a new key and the purge is not undone.
- **The revocation feed.** Decrypters cache keys. keysvc publishes every
  destroyed key ID on `/revocations`, and the aggregator polls it every 2 seconds
  and evicts. Purge latency is bounded by the poll interval, not the 5-minute
  cache TTL.

Retention is the same mechanism on a timer: keys older than `RETENTION_DAYS` are
destroyed.

→ `purge`, `destroy`, `retentionLoop` in [`cmd/keysvc/main.go`](../cmd/keysvc/main.go);
`followRevocations` in [`cmd/aggregator/main.go`](../cmd/aggregator/main.go);
tested by `TestPurge` and `TestRetention`

### 8. Refuse plaintext at the door

The collector only accepts a body that is exactly `{meta, sealed}`, where the
token's project owns the chunk and the key ID belongs to that project. Anything
else, such as an old client posting `{"lines": [...]}`, is refused before it
touches storage. The collector cannot decrypt; it checks shape and ownership.

→ `validate` in [`cmd/collector/main.go`](../cmd/collector/main.go), tested by
`TestValidate`

### 9. Keep plaintext off the node's disk

Encrypting in the sidecar is pointless if the container runtime has already
written the same lines to `/var/log/pods` on the node. The agent container's
entrypoint redirects stdout and stderr into named pipes (FIFOs) on an in-memory
`emptyDir`, and the sidecar reads the pipes. The runtime never sees the text, so
`kubectl logs` for the agent container is empty and nothing lands on the node.

→ [`deploy/agent.yaml`](../deploy/agent.yaml); CI checks the node's disk for the
test card number

## Threat model

| Attacker | Can they read log text? | Why | What they still get |
|---|---|---|---|
| Steals the bucket and ClickHouse | No | Only ciphertext and metadata are stored | Project and session IDs, timestamps, line counts, level counts, chunk sizes |
| Operator staff using the product | No | keysvc refuses `staff` unwrap; every attempt is audited | The metadata index |
| Another tenant | No | keysvc checks the token's project against the key's project | Nothing |
| Compromised collector | No | It never holds a key | It can drop chunks (availability). Changed metadata fails decryption |
| Someone who edits the metadata index | No | The aggregator decrypts with the metadata stored inside the object, which is authenticated | They can hide chunks from queries |
| Reads the node's disk | No | Agent output goes through in-memory FIFOs, never the runtime's log files | Nothing |
| Compromised aggregator | **Yes**, for anyone who queries while it is compromised | It decrypts in memory on the caller's behalf | Up to 5 minutes of cached keys per caller |
| Compromised keysvc **plus** KMS access | **Yes** | That pair can unwrap any key | Everything not yet purged |
| Compromised producer | **Yes**, its own pod's output | It sees the text before sealing | Nothing from other pods or days |
| Anyone, after a purge | No | The wrapped key is gone; the ciphertext is permanently unreadable | Ciphertext |

What this means:

- The design moves trust from "everything that touches logs" to two components:
  **keysvc + KMS** (who may unwrap) and **the aggregator** (where plaintext
  exists briefly). Those are small, auditable and can be isolated.
- **Metadata leaks.** Volume, timing, session IDs and "this chunk has errors" are
  visible to storage. If that matters, move fields into the ciphertext and accept
  coarser queries.
- **Compression leaks length.** Compressing before encrypting means chunk size
  depends on content. If an attacker can inject text into the same chunk as a
  secret and watch sizes, that is a [CRIME](https://en.wikipedia.org/wiki/CRIME)-style
  oracle. It is hard to exploit here (one seal per chunk, many lines per chunk),
  but it is not zero.
- **Purge is only as good as the key's copies.** Backups of keysvc's database hold
  wrapped keys; their retention must be shorter than your purge promise.

## Trade-offs

- **No server-side full-text index.** Search is a scan over decrypted chunks, so
  query cost grows with the time range. The metadata index (project, time,
  session, level) keeps that scan small. A searchable index would need blind
  tokens (an HMAC of each word, per project), which leak word frequency.
- **A keysvc round trip on the query path.** The first query for a day key per
  caller costs an unwrap. The per-caller cache makes the rest local.
- **Day keys set the purge granularity.** You can purge a day (or a range of
  days), not a single line. Generations let you purge "today so far".
- **Decryption happens server-side.** The aggregator sees plaintext. The
  alternative, decrypting in the customer's browser with a key the operator never
  holds, removes the aggregator from the trust boundary but makes key loss
  unrecoverable and server-side search impossible.
- **Producers must change.** The collector refuses plaintext, so every log source
  needs the sidecar or the SDK.

## What a production version needs

The prototype makes these simplifications on purpose:

- **Identity.** One shared HMAC secret mints every token, so anyone with the
  secret can be anyone. Production needs real project API tokens, workload
  identity for producers (projected service-account tokens) and SSO for people.
- **Pinned signing key.** Producers fetch keysvc's signing key from keysvc on
  first use. Production ships the signing key's public half to producers out of
  band.
- **Observer endpoints.** `/keys` and `/audit` answer any valid token so the demo
  can show them; `/revocations` answers anyone. Lock them down.
- **keysvc storage.** One replica on SQLite. Production wants a replicated
  database and several replicas, with the audit log in an append-only store.
- **KMS.** OpenBao runs in dev mode, in memory: if its pod restarts, every stored
  chunk is unreadable. Use a real KMS (OpenBao in HA, or a cloud KMS behind the
  `KeyWrapper` interface) and restrict unwrap to keysvc's identity.
- **Transport.** No TLS between services and no NetworkPolicy.

## Further reading

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [Envelope encryption (Google Cloud KMS docs)](https://cloud.google.com/kms/docs/envelope-encryption)
- [Crypto-shredding](https://en.wikipedia.org/wiki/Crypto-shredding)
- [OpenBao Transit secrets engine](https://openbao.org/docs/secrets/transit/)
- [Loki's storage design](https://grafana.com/docs/loki/latest/get-started/architecture/): a
  small label index plus chunks in object storage, the layout this prototype copies
- [AEAD and associated data](https://www.rfc-editor.org/rfc/rfc5116)
