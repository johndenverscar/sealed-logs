# Demo

This takes about 35 minutes. You're going to play a customer whose code logs a
card number by accident, and then go looking for it. By the end you'll have seen
that:

- it's encrypted before it leaves the pod;
- it isn't in the bucket, the index or on the node's disk;
- your project can read it, but operator staff and other customers can't;
- a client that tries to send plaintext gets turned away;
- once you purge the day, nobody can read it again, and new logs carry on as
  normal under a new key;
- a live tail shows each person exactly what a query would;
- support can read your logs only while you let them;
- only admins can do the dangerous things, and you can see everything anyone
  did with your keys;
- with your own KMS key, you can lock everyone out, the operator included.

[design.md](design.md) has the longer explanation of each piece if you want it.

## Getting set up

Start everything:

```sh
./up.sh
```

It opens http://127.0.0.1:7100 when it's done.

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

As `u_alice · project admin` you get an ordinary log viewer: a volume chart, a
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

## 10. Tail it live

Open the **Logs** tab in two browser windows side by side. Set one to
`u_alice · project admin` and the other to `s_bob · operator staff`, and tick
**Live tail** in both. A green **● Live** shows up next to it.

Now send a few lines from **Pipeline** (a third window, or switch back and
forth). Within about a second each line shows up at the top of Alice's table,
highlighted. In Bob's window a **Sealed** row arrives at the same moment: he can
see that something was logged, and when, but not what.

Click **stream** on the Pipeline tab to see where the tail got it from. The
collector published the same sealed chunk it stored, and the aggregator read it
off the topic and asked keysvc to unwrap with each viewer's own token, just like
a query. **aggregator** shows "opened the chunk for a live tail" for each of
them.

## 11. Give support temporary access

Stay on **Logs** as `s_bob · operator staff`. Above the chart there's a panel
saying you can see when and where the project logged, but not what. Pick
**2 min**, keep the reason, and click **Request access**. Nothing changes yet:
the panel says it's waiting for a member of `p_demo`.

Switch **Viewing as** to `u_alice · project admin` (or use the other window).
Alice sees Bob's request, with his reason. Click **Approve**.

Switch back to Bob. The panel turns orange with a countdown, and the rows that
were **Sealed** are now readable, live tail included. Click **keysvc** on the
Pipeline tab: Bob's unwraps are allowed, and each audit row names the grant and
that Alice approved it.

Then either wait out the two minutes or have Alice click **Revoke**. Within a
couple of seconds Bob's view reloads and everything is sealed again. The
aggregator dropped what it had cached for him, and keysvc refuses him until
someone approves a new grant.

Bob can't approve his own request, and neither can an admin of another
project. A grant only ever covers the one project that approved it.

## 12. Admins and viewers

On **Logs**, switch **Viewing as** to `u_carol · project viewer`. Carol reads
the project's logs like Alice does. If Bob has a request waiting, Carol sees it,
but instead of **Approve** she gets "Only p_demo admins can decide."

Open the **Security** tab. The **Members** table shows who can do what. Switch
its **Viewing as** to Carol: the access log answers "only admins of p_demo can
read its access log", and **Use my own KMS key** is refused too.

## 13. Read the access log

Switch back to `u_alice · project admin`. The **Access log** lists every
decision keysvc made about p_demo's keys and access, newest first: Alice's and
Carol's decrypts, Bob's refusals and his grant, Carol's refused attempt from the
last step. Tick **Operator staff and system only** to see just what the
operator's side did.

Above the table it says **Hash chain intact**. Each entry's hash covers the one
before it, so an edited or deleted entry would break it from there on.
`TestAccessLog` edits a row to prove that it's caught.

## 14. Bring your own key, then lock everyone out

Still on **Security** as Alice, click **Use my own KMS key**. The demo, playing
the customer, creates a key in the customer's KMS (the `customer-kms` pod) and a
token for keysvc that can only encrypt and decrypt with it. keysvc checks the
key works, then rewraps every live day key with it. The card shows how many.

The **Your KMS** box is the customer's side: the policy they've given the
operator. Click **Revoke operator decrypt**. That removes the decrypt line from
the policy, in the customer's KMS. Nobody tells keysvc.

Within a few seconds the card turns red, and the access log shows keysvc
noticing ("Own KMS key: decrypt unavailable"). On **Logs**, every row from a
live day key now says **Locked by your key**, even for Alice. Send a line from
**Pipeline**: it's still accepted and stored, and it's locked too.

Click **Restore operator decrypt**, and a few seconds later everything reads
again.

## What you saw

| What you saw | Where | The test that checks it |
|---|---|---|
| The line is encrypted in the pod, and only metadata leaves readable | Steps 1–2 | `TestCiphertextHidesText` |
| No plaintext in the bucket or the index | Steps 3 and 6 | `TestLifecycle` (live scan) |
| No plaintext on the node's disk | Step 7 | The `grep` in step 7 |
| Only members of the key's project can decrypt, and every decision is audited | Steps 4–5 | `TestUnwrapPolicy`, `TestLifecycle`, `TestLogsView` |
| Plaintext is refused at the door | Step 8 | `TestValidate`, `TestLifecycle` |
| Destroying a key deletes its logs everywhere, within about 2 seconds | Step 9 | `TestPurge` (keysvc and live) |
| A live tail decrypts for whoever is watching, and nobody else | Step 10 | Not automated |
| Support reads a project's logs only while an admin allows it | Step 11 | `TestSupportGrant` |
| Viewers can't purge, approve, read the access log or change keys | Step 12 | `TestPurge`, `TestSupportGrant`, `TestAccessLog`, `TestBYOK` |
| The access log shows edits and deletions | Step 13 | `TestAccessLog` |
| Taking decrypt away in the customer's KMS locks everyone out, and logs keep arriving | Step 14 | `TestBYOK` |
| Editing stored metadata stops the chunk from opening | Not in the demo | `TestMetadataIsBound` |

## Where to go next

- [break-it.md](break-it.md) takes the protections out one at a time, so you can
  see what each one is worth and which test notices.
- [design.md](design.md#threat-model) covers what this *doesn't* protect against.
- A new cluster starts with three past days of logs. Pick **7d** on the **Logs**
  tab to see them, or purge a single day with `./bin/logs --purge <YYYY-MM-DD>`.
