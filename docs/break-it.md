# Break it

Every protection in this repo is there for a reason, and the easiest way to see
the reason is to take it out. Each section below is a small change that removes
one protection. It tells you which test notices and what an attacker would get
with that protection gone.

Run the tests after each change, then undo it:

```sh
go test ./...                                    # unit tests, no cluster needed
./up.sh && SEALED_LIVE=1 go test ./cmd/demo -v   # end to end, against kind
git checkout -- .                                # put things back
```

## 1. Authenticate less of the metadata

In [`internal/envelope/envelope.go`](../internal/envelope/envelope.go), change
`aad` so it only covers the project, chunk ID and key ID:

```go
func aad(m Meta) []byte { return []byte(m.Project + "|" + m.ChunkID + "|" + m.KeyID) }
```

Then run `go test ./internal/envelope`.

`TestMetadataIsBound` fails. You can now change a chunk's session, agent,
source, timestamps, line count or level counts, and it still opens.

The metadata is readable so storage can index it, which means anyone who can
write to the bucket can edit it too. With only three fields protected, they
could:

- move a chunk's timestamps outside the range someone is searching, so an
  incident disappears from the investigation;
- relabel a session, so one user's activity looks like someone else's;
- set the error count to 0, so a "show me errors" query skips the chunk.

The log text stays secret either way. Integrity is its own problem, and
encrypting the text does nothing for the metadata unless you bind it in.

## 2. Forget to check the project

In [`cmd/keysvc/main.go`](../cmd/keysvc/main.go), in `unwrap`, delete the
`case c.Project != k.Project:` branch and the reason line under it.

Then run `go test ./cmd/keysvc`.

`TestUnwrapPolicy` fails on "other project's member". Any customer can now read
any other customer's logs, as long as they ask for the right key IDs, and key
IDs aren't secret: they're in every chunk's metadata.

You might expect the per-project key derivation in the KMS to catch this. It
doesn't. keysvc passes the key's own project as the derivation context, so the
unwrap goes through. A protection that sits behind a policy check is only as good
as what the policy hands it. A real deployment would also limit keysvc's KMS
credentials, so it could only unwrap in a context the caller had proved it owns.

## 3. Let one support grant open every project

Support staff can read a project's logs only while a member of that project has
approved a grant. In [`cmd/keysvc/main.go`](../cmd/keysvc/main.go), in
`activeGrant`, stop matching the grant's project:

```go
rows, err := s.db.Query(`SELECT `+grantCols+` FROM grants WHERE grantee=? AND (project=? OR 1=1) AND status='active'`, sub, project)
```

Then run `go test ./cmd/keysvc`.

`TestSupportGrant` fails on "p_demo grant opened a p_other key". One customer
said yes, and now the support engineer can read every customer's logs for the
next hour.

The approval is only worth anything if it's scoped to what the approver owns. A
member of p_demo can speak for p_demo, and for nobody else. The same goes for
who approves: drop the `member` check in `decideGrant` and staff can approve
their own requests, which is a standing decrypt path with extra steps.

## 4. Let plaintext in

In [`cmd/collector/main.go`](../cmd/collector/main.go), in `validate`, delete the
call to `unsealedReason`.

Then run `go test ./cmd/collector`. For the live version, rebuild with `./up.sh`,
then click **Send plaintext (old client)** and **Scan storage** in the demo.

`TestValidate` fails on "sealed chunk + plaintext". A perfectly good encrypted
chunk with the plaintext lines tagging along in a `lines` field now gets
accepted, and the collector stores the whole body as it is.

The collector can't decrypt, so it has no way to check that the ciphertext
matches anything. All it can check is the shape of the request. Allowing only
`meta` and `sealed` at the top level is a cheap check, and it's what stops a
buggy or outdated client from quietly writing plaintext to storage.

## 5. Purge without telling anyone

In [`cmd/keysvc/main.go`](../cmd/keysvc/main.go), in `destroy`, delete the
`INSERT INTO revocations` line.

Then run `go test ./cmd/keysvc`. For the live version, rebuild, send a line,
read it as a project member, click **Purge today** and read it again.

`TestPurge` fails because no revocation gets published. In the live version the
member can still read the "purged" logs for up to 5 minutes, because the
aggregator still has the key cached.

Crypto-shredding is only as fast as your slowest cache. You can keep the cache
short (more unwraps, slower queries) or announce purges so caches can evict (a
purge shows up in about 2 seconds, and the cache can stay long). This repo does
both.

## 6. Let the runtime keep a copy

In [`deploy/agent.yaml`](../deploy/agent.yaml), change the `agent` container's
command so it stops redirecting into the named pipes:

```yaml
command: [producer, fakeagent, --listen, ":8080"]
```

Run `./up.sh`, send the card-number line from the demo, then:

```sh
kubectl --context kind-sealed -n sealed-logs logs deploy/agent -c agent
docker exec sealed-control-plane grep -rl "4111 1111" /var/log/pods
```

The card number shows up in `kubectl logs` and in a file under `/var/log/pods` on
the node.

Every storage check still passes, because the sidecar still encrypted everything
it shipped. The leak happens before encryption: the container runtime grabbed
stdout first. Nothing in the logging pipeline itself is wrong, which is exactly
why this one is easy to miss.

The sidecar has nothing to read now, so the demo shows the agent step and then
stops. Put things back with `git checkout deploy/agent.yaml && ./up.sh`.

## Things I didn't build

- **Hiding more metadata.** Moving `session_id` inside the ciphertext would hide
  who was logging. The cost is that per-session queries would have to decrypt
  every chunk.
- **Searchable encryption.** A per-project HMAC "blind index" of words would let
  the aggregator skip chunks that can't match. It would also leak how often each
  word appears to anyone who sees enough queries.
- **Customer-held keys.** Wrapping day keys with a key the customer controls
  (their own KMS, or a passkey in the browser) takes the platform out of the
  picture entirely. It also means a customer who loses their key loses their
  logs.
