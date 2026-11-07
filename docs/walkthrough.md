# Walkthrough

Eight steps, about 20 minutes. You play a customer whose code logs a card number
by accident, then you check where that number went. Each step says what to do,
what you should see, and why it matters. [design.md](design.md) explains the
ideas in depth.

Start the stack and the harness:

```sh
./up.sh
./bin/tui
```

The TUI has three parts:

- **The pipeline** along the top: `agent → sidecar → collector → bucket → clickhouse → aggregator → keysvc → viewer`.
  A box lights up when that component handles your line, coloured by what it
  held: orange for plaintext, teal for sealed data only, purple for key material,
  red for a denial.
- **Compose** on the left, where you write the line your "customer code" prints.
- **Inspect** on the right, which shows what the selected component received and produced.

In the composer, `↑`/`↓` move between fields, `←`/`→` change the level and
stream, `Ctrl+U` clears a field and `Enter` sends. `Esc` leaves the composer for
navigation, where `←`/`→` (or `1`–`8`) pick a component; `Tab` goes back to the
composer. The bottom line always lists the keys.

## 1. Log a secret

The composer is pre-filled with a line that leaks a card number. Change the
level to `error` and the stream to `stderr` if you like, then press `Enter`.

**You should see** the agent, sidecar, collector, bucket and clickhouse boxes
light up within about 2 seconds.

**Why:** the agent printed the line to stdout or stderr. Both are named pipes that
the sidecar reads, so the line never reached the container runtime. The sidecar
buffered it, compressed and sealed the chunk, and posted it to the collector.

## 2. Look at what the sidecar sent

Press `Esc`, then `2` (sidecar).

**You should see** the chunk's metadata (project, session, time range, level
counts), the public key it used with "ed25519 verified", and hex previews of
`enc` (the HPKE ephemeral key) and `ct` (the ciphertext). The message text is
not in the event.

**Why:** that metadata is all storage will ever be able to read. The sidecar
verified the public key's signature before sealing, so it can't have been
tricked into using someone else's key.

## 3. Look at what was stored

Press `4` (bucket), then `5` (clickhouse).

**You should see** the stored object (`meta` plus `sealed`) and the index row,
each with a check that reads **"message text: not found"**.

Open ClickHouse's SQL UI and look for yourself:

```sh
open 'http://127.0.0.1:18123/play?user=sealed&password=sealed'
```

```sql
SELECT * FROM sealed.log_chunks ORDER BY ingested_at DESC LIMIT 5
```

**Why:** an attacker with the bucket and the database learns that project
`p_demo` logged one error in session `ses_demo` at a given time. They don't learn
what it said.

## 4. Read it as three different people

Press `m`, then `s`, then `o`.

**You should see:**

- `m`, a project member: the line, decrypted.
- `s`, operator staff: ciphertext only, with the reason `role "staff" has no decrypt path`.
- `o`, a member of another project: ciphertext only, with the reason `token project "p_other" is not key project "p_demo"`.

Press `7` (keysvc) to see the audit rows: one allowed unwrap and two denials,
each with its reason.

**Why:** all three queries went through the same aggregator, which has no keys of
its own. It asked keysvc to unwrap with each caller's token, and keysvc applied
one rule: members of the key's project, and no one else.

## 5. Scan storage like an attacker

Press `g`.

**You should see** something like `object store: 1 objects, 0 hits · ClickHouse: 1 rows, 0 hits`.

The same scan from the CLI:

```sh
./bin/logs --scan
```

**Why:** the scan reads every object and row and looks for card numbers, SSNs and
your exact message. Zero hits is the property the whole design exists for.

## 6. Check the node's disk

In another terminal:

```sh
docker exec sealed-control-plane grep -rl "4111 1111" /var/log/pods; echo "exit $?"
kubectl --context kind-sealed -n sealed-logs logs deploy/agent -c agent
```

**You should see** no files (`exit 1`) and empty `kubectl logs` output.

**Why:** on a normal Kubernetes node, the container runtime writes every line a
container prints to `/var/log/pods`, in plaintext, before any sidecar can
encrypt it. The FIFO redirect in [`deploy/agent.yaml`](../deploy/agent.yaml)
closes that gap.

## 7. Send plaintext like an old client

Press `x`.

**You should see** `old SDK sent plaintext → collector 422 … plaintext logs are refused`.

**Why:** the collector accepts only `{meta, sealed}`. A client that hasn't been
upgraded fails loudly instead of quietly writing plaintext to storage.

## 8. Purge today

Press `p`, then `m`.

**You should see** `purged <today>: destroyed 1 key(s)`, then the member's query
returns `destroyed` for today's chunks. The bucket still holds the same objects.

Wait a few seconds (the sidecar caches the public key for 5 seconds), then send
another line (`Tab`, type, `Enter`) and read it as a member again.

**You should see** the new line decrypt. Its key ID ends in `/g2`.

**Why:** destroying a key is the delete. The ciphertext stays where it is, along
with any backups of it, and none of it can be read again. The aggregator dropped
its cached copy of the key within 2 seconds because it follows keysvc's
revocation feed. New logs go to a new key generation, so the purge doesn't
affect them.

## Where next

- [exercises.md](exercises.md): break the design on purpose and watch the tests catch it.
- [design.md](design.md#threat-model): what this does *not* protect against.
- `SEED=1 ./up.sh` writes three past days of logs, so you can try `./bin/logs --as member --since 96h`
  and purge a single day with `./bin/logs --purge <YYYY-MM-DD>`.
