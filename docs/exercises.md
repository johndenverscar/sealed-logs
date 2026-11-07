# Exercises: break it on purpose

Each exercise removes one protection. Make the change, run the tests, and watch
what catches it. Then think about what an attacker could do with that
protection gone before you open the answer.

```sh
go test ./...                 # unit tests: no cluster needed
./up.sh && SEALED_LIVE=1 go test ./cmd/tui -v   # end to end, against kind
git checkout -- .             # undo the change afterwards
```

## 1. Authenticate less metadata

In [`internal/envelope/envelope.go`](../internal/envelope/envelope.go), change
`aad` so it binds only the project, chunk ID and key ID:

```go
func aad(m Meta) []byte { return []byte(m.Project + "|" + m.ChunkID + "|" + m.KeyID) }
```

Run `go test ./internal/envelope`.

<details>
<summary>What catches it, and why it matters</summary>

`TestMetadataIsBound` fails: changing the session, agent, source, timestamps,
line count or level counts no longer stops the chunk from opening.

The metadata is plaintext so storage can index it, so anyone with write access to
the bucket can edit it. With only three fields bound, they could:

- move a chunk's timestamps outside a query's range, hiding an incident from
  the people investigating it;
- relabel a session, pinning one user's activity on another;
- set `n_error` to 0, so "show me errors" filters skip the chunk.

The text stays secret either way. Integrity is a separate property, and
encrypting the text gives you nothing for the metadata unless you bind it.
</details>

## 2. Forget the project check

In [`cmd/keysvc/main.go`](../cmd/keysvc/main.go), in `unwrap`, delete the
`case c.Project != k.Project:` branch and its reason line.

Run `go test ./cmd/keysvc`.

<details>
<summary>What catches it, and why it matters</summary>

`TestUnwrapPolicy` fails on "other project's member": any customer can now read
any other customer's logs by asking for their key IDs. Key IDs are not secret,
since they are in every chunk's metadata.

Notice that the per-project key derivation in the KMS does **not** save you.
keysvc passes the key's own project as the derivation context, so the unwrap
succeeds. A defence that sits behind the policy check is only as good as the
inputs the policy passes it. In production you would also scope the KMS
credentials so keysvc can unwrap only in a context the caller proved it owns.
</details>

## 3. Let support staff decrypt

A support engineer asks for read access "just for debugging". In `unwrap`, change
the role check to:

```go
case c.Role != auth.RoleMember && c.Role != auth.RoleStaff:
```

Run `go test ./cmd/keysvc`.

<details>
<summary>What catches it, and why it matters</summary>

`TestUnwrapPolicy` fails on "staff" and "staff claiming the project".

With this change, the promise to customers turns back into "we have a policy"
instead of "we can't". If support really needs access, model it as a grant
the customer gives: a time-limited, audited, project-scoped token that a
project member issues, so keysvc's rule ("members of the key's project") does
not change.
</details>

## 4. Open the door to plaintext

In [`cmd/collector/main.go`](../cmd/collector/main.go), in `validate`, delete the
call to `unsealedReason`.

Run `go test ./cmd/collector`. Then rebuild with `./up.sh`, press `x` in the TUI,
and press `g`.

<details>
<summary>What catches it, and why it matters</summary>

`TestValidate` fails on "sealed chunk + plaintext": a valid sealed chunk with
the plaintext lines riding alongside it in a `lines` field is now accepted, and
the collector stores the whole body as-is.

The collector cannot decrypt, so it can't check that the ciphertext matches
anything. All it can enforce is shape. An allowlist of top-level fields
(`meta`, `sealed`, nothing else) is the cheapest control that stops a buggy or
outdated client from quietly writing plaintext to storage.
</details>

## 5. Purge without telling anyone

In [`cmd/keysvc/main.go`](../cmd/keysvc/main.go), in `destroy`, delete the
`INSERT INTO revocations` line.

Run `go test ./cmd/keysvc`. For the live version, rebuild, send a line, read it
as a member (`m`), purge (`p`) and read again.

<details>
<summary>What catches it, and why it matters</summary>

`TestPurge` fails because no revocation is published. Live, the member can still
read the "purged" logs for up to 5 minutes, because the aggregator still holds
the unwrapped key in its cache.

Crypto-shredding is only as fast as your slowest cache. You can bound purge
latency with a short TTL (more unwraps, slower queries) or with a revocation
feed (purge is visible in about 2 seconds while the TTL stays long). This
design uses both.
</details>

## 6. Let the runtime keep a copy

In [`deploy/agent.yaml`](../deploy/agent.yaml), change the `agent` container's
command so it no longer redirects into the FIFOs:

```yaml
command: [producer, fakeagent, --listen, ":8080"]
```

Run `./up.sh`, send the card-number line from the TUI, then:

```sh
kubectl --context kind-sealed -n sealed-logs logs deploy/agent -c agent
docker exec sealed-control-plane grep -rl "4111 1111" /var/log/pods
```

<details>
<summary>What catches it, and why it matters</summary>

The card number shows up in `kubectl logs` and in a file under `/var/log/pods` on
the node. CI's "no plaintext on the node's disk" step fails.

The sidecar still sealed everything it shipped, so every storage check still
passes. The leak is upstream of the encryption: the container runtime captured
stdout first. It's the easiest gap to miss, because nothing in the logging
pipeline itself is wrong.

The sidecar has nothing to read now, so the TUI shows the agent step and then
nothing. Put the redirect back with `git checkout deploy/agent.yaml && ./up.sh`.
</details>

## Open-ended

- **Hide more metadata.** Move `session_id` into the ciphertext. Which queries
  get slower, and which ones become impossible?
- **Searchable encryption.** Add a per-project HMAC "blind index" of words so the
  aggregator can skip chunks that can't match. What does it leak to someone who
  sees many queries?
- **Customer-held keys.** Wrap day keys with a key the customer controls (their
  KMS, or a passkey in the browser). What happens to purge, to support, and to
  a customer who loses the key?
