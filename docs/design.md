# Design

This is the longer version: what problem this is trying to solve, the ideas
that make it work, what it does and doesn't protect against, and what it gives
up. Each idea links to the code that implements it.

- [The problem](#the-problem)
- [How it works](#how-it-works)
- [Threat model](#threat-model)
- [Trade-offs](#trade-offs)
- [What a production version needs](#what-a-production-version-needs)
- [References](#references)

## The problem

When a platform runs customer code, it collects that code's logs and shows them
back to the customer in a log viewer. Those logs hold whatever the code printed,
and sooner or later that includes card numbers, transcripts, API keys or health
data. A typical pipeline stores every line in plaintext, which has a few
uncomfortable consequences:

- Anyone who gets the bucket or the log database can read every customer's logs.
- Anyone on staff with database access can read them too. The customer's only
  protection is a policy that says they won't.
- Deleting a customer's data means tracking down and rewriting every copy,
  backups and replicas included.

What I wanted instead: the platform still stores and indexes the logs, but only
people in the customer's own project can read them, and deleting a key is enough
to delete the data.

## How it works

### 1. Encrypt at the source, to a public key

The producer encrypts each chunk of log lines before it leaves the pod. Here
that's a sidecar next to the customer's container; it could just as well be an
SDK inside it. It encrypts to the project's *public* key, so the producer never
holds anything that could decrypt, not even its own earlier output.

The scheme is [HPKE](https://www.rfc-editor.org/rfc/rfc9180) (RFC 9180) with
X25519, HKDF-SHA256 and AES-256-GCM. HPKE makes a fresh one-time key for every
chunk, so two identical chunks never come out as the same ciphertext.

→ `Seal` and `Open` in [`internal/envelope/envelope.go`](../internal/envelope/envelope.go)

### 2. Compress first, then encrypt

Ciphertext doesn't compress, so lines are written as JSON Lines and compressed
with zstd before they're encrypted. Each chunk holds up to 64 lines or 2 seconds
of output from one session, whichever comes first, and one HPKE operation covers
the whole chunk. That way the public-key cost is paid once per chunk rather than
once per line.

→ the sidecar's flush loop in [`cmd/producer/main.go`](../cmd/producer/main.go)

### 3. Readable metadata that can't be tampered with

Storage needs something to index, so each chunk carries a small metadata record:
project, session, agent, time range, number of lines and a count per log level.
It never carries any log text.

The metadata is readable, but it's tied to the ciphertext as AEAD *additional
authenticated data*. Change any field (move the chunk to another project, shift
its timestamps, relabel its session) and the chunk no longer decrypts. Storage
can read the index, but it can't lie with it.

→ `aad` in [`internal/envelope/envelope.go`](../internal/envelope/envelope.go),
checked by `TestMetadataIsBound`

### 4. One key pair per project per day, wrapped by a KMS

keysvc creates a key pair for each project for each UTC day, with IDs like
`p_demo/2026-11-07/g1`. It never stores a private key in the clear. Instead it
wraps the private key with a master key that lives in a KMS (OpenBao Transit,
here) and keeps only the wrapped copy.

The master key is derived separately for each project (Transit's `derived` mode,
with the project ID as context), so a key wrapped for one project won't unwrap
under another project's context.

keysvc also signs every public key with Ed25519, and producers check the
signature before encrypting anything. If someone tampers with a `/pubkey`
response, the producer refuses the key instead of encrypting to an attacker.

→ [`cmd/keysvc/main.go`](../cmd/keysvc/main.go),
[`internal/wrap/wrap.go`](../internal/wrap/wrap.go)

### 5. One rule decides who can read

There's exactly one way to turn a wrapped key back into a usable private key:
keysvc's `/unwrap`. It hands the key over only if the caller's token has the
`member` role and its project matches the key's project. Staff, producers and
members of other projects are all refused. Every decision, yes or no, goes into
an audit table.

→ `unwrap` in [`cmd/keysvc/main.go`](../cmd/keysvc/main.go), checked by
`TestUnwrapPolicy`

### 6. Decrypt at query time, as the person asking

The aggregator answers log queries, and it doesn't have standing access to any
key. For each query it:

1. uses the ClickHouse index to find the chunks that could match (project, time
   range, session, whether there were errors);
2. fetches those encrypted chunks from the bucket;
3. asks keysvc to unwrap each day key using *the caller's own token*;
4. decrypts and filters the lines in memory, then throws them away.

Unwrapped keys are cached for 5 minutes, per caller and per key, so one person's
access never ends up serving someone else's query.

Search (`--q 4111`) runs on the decrypted text, after the fact. That's why
searching for `4111` also finds `4-1-1-1` or `4🙂1🙂1🙂1`: no index ever saw the
text, so the search is free to be flexible.

→ [`cmd/aggregator/main.go`](../cmd/aggregator/main.go)

### 7. Delete the key, not the data

This is usually called crypto-shredding. Purging a day destroys that day's
wrapped private keys. The ciphertext stays in the bucket, and now it can never be
read. Nothing has to go find and rewrite every copy, because backups and replicas
of the bucket become unreadable at the same moment.

Two details make that hold up in practice:

- **Generations.** After a mid-day purge, the next `/pubkey` call creates
  generation 2 (`…/g2`). New logs go to the new key, so they don't quietly undo
  the purge.
- **The revocation feed.** Anything that decrypts also caches keys, and a cached
  key would keep working after a purge. keysvc publishes every destroyed key ID
  on `/revocations`, and the aggregator checks it every 2 seconds and evicts. So
  a purge takes effect in about 2 seconds, not after the 5-minute cache expires.

Retention works the same way on a timer: keys older than `RETENTION_DAYS` get
destroyed.

→ `purge`, `destroy` and `retentionLoop` in [`cmd/keysvc/main.go`](../cmd/keysvc/main.go);
`followRevocations` in [`cmd/aggregator/main.go`](../cmd/aggregator/main.go);
checked by `TestPurge` and `TestRetention`

### 8. Turn plaintext away at the door

The collector only accepts a body that's exactly `{meta, sealed}`, where the
token's project owns the chunk and the key ID belongs to that project. Anything
else, like an old client posting `{"lines": [...]}`, is refused before it gets
near storage. The collector can't decrypt, so it can't check what's inside. It
checks the shape and who owns it, and that turns out to be enough.

→ `validate` in [`cmd/collector/main.go`](../cmd/collector/main.go), checked by
`TestValidate`

### 9. Keep plaintext off the node's disk

Encrypting in the sidecar doesn't help much if the container runtime has
already written the same lines to `/var/log/pods` on the node. So the agent
container's entrypoint sends stdout and stderr into named pipes on an in-memory
`emptyDir`, and the sidecar reads from those. The runtime never sees the text:
`kubectl logs` for the agent container is empty, and nothing lands on the node.

→ [`deploy/agent.yaml`](../deploy/agent.yaml); CI checks the node's disk for the
test card number

## Threat model

| Who | Can they read the logs? | Why | What they still get |
|---|---|---|---|
| Someone who steals the bucket and ClickHouse | No | Only ciphertext and metadata are stored | Project and session IDs, timestamps, line counts, level counts, chunk sizes |
| Operator staff using the product | No | keysvc refuses `staff`, and every attempt is audited | The metadata index |
| Another customer | No | keysvc checks the token's project against the key's project | Nothing |
| A compromised collector | No | It never holds a key | It can drop chunks. Anything it edits fails to decrypt |
| Someone who edits the metadata index | No | The aggregator decrypts using the metadata stored inside the object, which is authenticated | They can hide chunks from queries |
| Someone reading the node's disk | No | The agent's output goes through in-memory pipes, never the runtime's log files | Nothing |
| A compromised aggregator | **Yes**, for anyone who queries while it's compromised | It decrypts in memory on the caller's behalf | Up to 5 minutes of cached keys per caller |
| A compromised keysvc **and** KMS access | **Yes** | Together they can unwrap any key | Everything that hasn't been purged |
| A compromised producer | **Yes**, for its own pod's output | It sees the text before encrypting it | Nothing from other pods or other days |
| Anyone, after a purge | No | The key is gone, so the ciphertext can't be opened | Ciphertext |

A few things fall out of that table.

Instead of trusting everything that touches logs, you're trusting two things:
keysvc plus the KMS, which decide who can unwrap, and the aggregator, where
plaintext exists for a moment. Both are small enough to audit and isolate.

The metadata does leak. Storage can see volume, timing, session IDs and whether
a chunk had errors. If that matters to you, move fields inside the ciphertext and
accept coarser queries.

Compressing before encrypting leaks length. A chunk's size depends on what's in
it, so if an attacker can get their own text into the same chunk as a secret and
watch the sizes, that's a [CRIME](https://en.wikipedia.org/wiki/CRIME)-style
attack. It's hard to pull off here, with one encryption per chunk and many lines
per chunk, but it isn't impossible.

And a purge is only as good as the copies of the key. Backups of keysvc's
database contain wrapped keys, so they need to expire sooner than you've promised
deletion.

## Trade-offs

- **No server-side full-text index.** Search scans decrypted chunks, so a longer
  time range means a slower query. The metadata index (project, time, session,
  level) keeps the scan small. A searchable index would need blind tokens (a
  per-project HMAC of each word), and those leak how often each word appears.
- **An extra hop to keysvc on queries.** The first time a caller needs a given
  day key, it costs an unwrap. After that it comes from the per-caller cache.
- **You purge by the day.** Day keys mean you can delete a day or a range of
  days, not a single line. Generations let you purge "today so far".
- **Decryption happens on the server.** The aggregator sees plaintext. The
  alternative is decrypting in the customer's browser with a key the platform
  never holds. That takes the aggregator out of the picture, but a lost key means
  lost logs, and server-side search stops being possible.
- **Producers have to change.** The collector refuses plaintext, so every log
  source needs the sidecar or the SDK.

## What a production version needs

The demo takes some shortcuts on purpose:

- **Identity.** One shared HMAC secret signs every token, so anyone with the
  secret can be anyone. A real version needs real project API tokens, workload
  identity for producers (projected service-account tokens) and SSO for people.
- **A pinned signing key.** Producers fetch keysvc's signing key from keysvc the
  first time they need it. A real version would ship that public key to
  producers separately.
- **Open debug endpoints.** `/keys` and `/audit` answer any valid token so the
  demo can show them, and `/revocations` answers anyone. Those need locking down.
- **keysvc's storage.** It's one replica on SQLite. A real version wants a
  replicated database, several replicas and an append-only store for the audit
  log.
- **The KMS.** OpenBao runs in dev mode, in memory. If its pod restarts, every
  stored chunk becomes unreadable. Use a real KMS (OpenBao with HA, or a cloud
  KMS behind the `KeyWrapper` interface) and only let keysvc's identity unwrap.
- **The network.** There's no TLS between services and no NetworkPolicy.

## References

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [Envelope encryption (Google Cloud KMS docs)](https://cloud.google.com/kms/docs/envelope-encryption)
- [Crypto-shredding](https://en.wikipedia.org/wiki/Crypto-shredding)
- [OpenBao Transit secrets engine](https://openbao.org/docs/secrets/transit/)
- [Loki's storage design](https://grafana.com/docs/loki/latest/get-started/architecture/):
  a small label index plus chunks in object storage, which is the layout this
  repo borrows
- [RFC 5116: AEAD and associated data](https://www.rfc-editor.org/rfc/rfc5116)
