# Demo

This takes about 20 minutes. You're going to play a customer whose code logs a
card number by accident, and then go looking for it. By the end you'll have seen
that:

- it's encrypted before it leaves the pod;
- it isn't in the bucket, the index or on the node's disk;
- your project can read it, but operator staff and other customers can't;
- a client that tries to send plaintext gets turned away;
- once you purge the day, nobody can read it again, and new logs carry on as
  normal under a new key.

[design.md](design.md) has the longer explanation of each piece if you want it.

## Getting set up

Start the cluster and the demo server, then open the page:

```sh
./up.sh
./bin/demo
open http://127.0.0.1:7100
```

The page has two tabs.

**Pipeline** is where you play the customer. Along the top are the components a
log line passes through, `agent → sidecar → collector → bucket → clickhouse →
aggregator → keysvc → viewer`. A box lights up when that component handles your
line, and the colour tells you what it was holding: orange for plaintext, teal
for encrypted data, purple for key material and red for a refusal. Click a box
to see what it received and what it did with it in the inspector on the right.
On the left is the composer, where you write the line your "customer code"
prints, and the buttons that act on it. At the bottom is the line's lifecycle,
step by step.

**Logs** is the log viewer a customer would use in the product. It queries the
same aggregator, as whichever person you pick in **Viewing as**.

## 1. Log a secret

On the **Pipeline** tab the composer starts with a line that leaks a card number.
Set the level to `error` and the stream to `stderr` if you like, then click
**Send**.

Within a couple of seconds the agent, sidecar, collector, bucket and clickhouse
boxes should light up.

The agent printed the line, but stdout and stderr in that container are named
pipes, so the line went to the sidecar instead of the container runtime. The
sidecar held onto it briefly, compressed and encrypted the chunk, and sent it to
the collector.

## 2. See what the sidecar sent

Click the **sidecar** box.

You'll see the chunk's metadata (project, session, time range, how many lines at
each level), the public key it used marked "ed25519 verified", and a hex preview
of `enc` (HPKE's one-time key) and `ct` (the ciphertext). Your message isn't
anywhere in there.

That metadata is all storage will ever be able to read. The sidecar also checked
keysvc's signature on the public key before using it, so nobody could have
slipped it a different key.

## 3. See what got stored

Click **bucket**, then **clickhouse**.

You'll see the stored object (`meta` plus `sealed`) and the index row, each read
live from the store, with a check that says **"message text: not found"**.

If you'd rather look for yourself, open ClickHouse's SQL UI:

```sh
open 'http://127.0.0.1:18123/play?user=sealed&password=sealed'
```

```sql
SELECT * FROM sealed.log_chunks ORDER BY ingested_at DESC LIMIT 5
```

Someone who stole the bucket and the database would learn that project `p_demo`
logged one error in session `ses_demo` at a certain time. They wouldn't learn
what it said.

## 4. Read it as three different people

Under **Read the selected line as**, click **Project member**, then **Operator
staff**, then **Other project**.

- The project member gets the line back, decrypted.
- Operator staff get ciphertext and the reason `role "staff" has no decrypt path`.
- A member of a different project gets ciphertext and the reason
  `token project "p_other" is not key project "p_demo"`.

Click **keysvc** to look at its audit log: one unwrap allowed, two refused, each
with its reason. **viewer** shows exactly what each person got back.

All three queries went through the same aggregator, and the aggregator doesn't
hold any keys. It asked keysvc to unwrap the key using each person's own token,
and keysvc has exactly one rule: members of the key's project, nobody else.

## 5. See it the way the customer does

Switch to the **Logs** tab.

As `u_alice · project member` you get an ordinary log viewer: a volume chart, a
table of lines with level, time, source and session, and filters down the side.
Click your line to open its details and attributes. Type `level:error` or
`session:ses_demo` into the filter box, or any text, and press Enter.

Now switch **Viewing as** to `s_bob · operator staff`. The same chunks are still
there, because the index is readable, but every row says **Sealed** with
keysvc's reason and a slice of ciphertext. Staff can see that the project logged
an error in session `ses_demo` and when. They can't see what it said. The chart
still shows volume, hatched, for the same reason. `u_mallory · other project`
gets the same.

The search box makes the point too. Search for `4111` as the member and the line
comes back. Search runs after decryption, so it works on the text without any
index ever having seen it.

## 6. Scan storage like an attacker would

Back on **Pipeline**, click **Scan storage**.

You'll see something like `object store: 1 objects, 0 hits · ClickHouse: 1 rows, 0 hits`.
The CLI can do the same scan:

```sh
./bin/logs --scan
```

It reads every object and every row and looks for card numbers, SSNs and the
exact message you sent. Zero hits is the whole point of the project.

## 7. Check the node's disk

In a terminal:

```sh
docker exec sealed-control-plane grep -rl "4111 1111" /var/log/pods; echo "exit $?"
kubectl --context kind-sealed -n sealed-logs logs deploy/agent -c agent
```

The `grep` finds nothing (`exit 1`) and `kubectl logs` prints nothing.

This one's easy to miss. On a normal Kubernetes node the container runtime writes
everything a container prints to `/var/log/pods`, in plaintext, before a sidecar
ever gets a chance to encrypt it. The named-pipe redirect in
[`deploy/agent.yaml`](../deploy/agent.yaml) is what closes that gap.

## 8. Send plaintext like an old client

Click **Send plaintext (old client)**.

You'll see `old SDK sent plaintext → collector 422 … plaintext logs are refused`.

The collector only accepts encrypted chunks. A client that hasn't been upgraded
fails loudly, which is much better than quietly writing plaintext to storage.

## 9. Purge today

Click **Purge today** and confirm, then read the line as **Project member**
again.

You'll see `Purged <today>: destroyed 1 key(s)`, and then the member's read comes
back with `destroyed`. On the **Logs** tab, today's rows now say **Key
destroyed**, even for the member. The bucket still has every object it had a
minute ago.

Wait a few seconds (the sidecar caches the public key for 5), then send another
line and read it as a member again. This time it decrypts, under a new key
generation (`/g2` after the first purge of the day).

Destroying the key *is* the delete. The ciphertext stays where it is, along with
any backup of it, and none of it can be read again. The aggregator had a copy of
the key cached, but it watches keysvc's list of destroyed keys and dropped it
within 2 seconds. New logs get a fresh key, so they aren't affected.

## What you saw

| What you saw | Where | The test that checks it |
|---|---|---|
| The line is encrypted in the pod, and only metadata leaves readable | Steps 1–2 | `TestCiphertextHidesText` |
| No plaintext in the bucket or the index | Steps 3 and 6 | `TestLifecycle` (live scan) |
| No plaintext on the node's disk | Step 7 | The `grep` in step 7 |
| Only members of the key's project can decrypt, and every decision is audited | Steps 4–5 | `TestUnwrapPolicy`, `TestLifecycle`, `TestLogsView` |
| Plaintext is refused at the door | Step 8 | `TestValidate`, `TestLifecycle` |
| Destroying a key deletes its logs everywhere, within about 2 seconds | Step 9 | `TestPurge` (keysvc and live) |
| Editing stored metadata stops the chunk from opening | Not in the demo | `TestMetadataIsBound` |

## Where to go next

- [break-it.md](break-it.md) takes the protections out one at a time, so you can
  see what each one is worth and which test notices.
- [design.md](design.md#threat-model) covers what this *doesn't* protect against.
- `SEED=1 ./up.sh` writes three past days of logs. Pick **7d** on the **Logs**
  tab to see them, or purge a single day with `./bin/logs --purge <YYYY-MM-DD>`.
