# From the demo to a client environment

**What this document is.** The hosted instance at Railway exists to be shown to people. It runs the
real engine, makes real model calls and enforces real access control — but on fabricated data, and
on a third-party platform. This is the list of what must change before a hosted instance is allowed
anywhere near real client logs, screenshots or source, and *why* each item is on it.

It is deliberately specific about what the demo gets away with. A migration guide that reads like a
feature list is useless; the value is in the sentences that say "this worked because nothing here
mattered."

**Who this is for.** Whoever deploys this into a client estate, and whoever has to sign it off. Read
it alongside `SECURITY.md` (the threat model and the screenshot decision), `ARCHITECTURE.md` (how the
pieces fit) and `DATA_MODEL.md` §8 (the PostgreSQL port, already done).

---

## 1. What the demo changes about the security model

The product's security argument, from the beginning, is one sentence: **client logs, screenshots and
source never leave the estate that captured them.** Everything in `SECURITY.md` rests on it. Three
things about the demo would break that argument if the data were real.

### 1.1 Mode 0's strongest claim stops being true

`SECURITY.md` §3.3: *"Mode 0 creates no copy of any screenshot. The image is read only to record its
path, size and dimensions; the file stays on the bot VM share under the ACLs the estate already
applies. There is no bucket to secure, no lifecycle rule to verify, and no deletion job to prove —
because there is nothing to delete."*

That is the best argument in the document, and it is an argument about a **filesystem**, not about a
policy. It holds because the scanner reads a share the reader could already reach.

Upload a screenshot through a web form and it is gone: the image is now bytes in an HTTP request, in
a worker's memory, and — if anything is ever stored — on the server's disk. There *is* something to
delete.

**And the demo now uploads whole folders, which is a larger exposure than a single file, not a
smaller one.** The Analyse tab rebuilds the dropped tree on the server's disk — logs, source and
every screenshot — and holds it while the reviewer decides. Two things bound it, and both are
deliberate: `screenshot.processing_mode` stays 0 so the image is never read or sent, and an
abandoned review is swept after thirty minutes with its tree deleted. That is a retention policy in
all but name, which is the point: Q3 and Q4 (how long, and who may view) are no longer questions a
hosted instance can defer. The *structural* claim — that there is nothing to delete because nothing
was copied — is gone the moment the transport changes.

**What must change.** Decide, explicitly, whether a hosted instance accepts screenshot uploads at
all. If it does, `SECURITY.md` §3 needs rewriting around a new premise, and Q3 and Q4 (retention and
who may view) stop being deferrable — they become the design.

### 1.2 Access control stops being inherited and becomes ours

On the CLI, a person sees what the Windows share lets them see. Eagle Eyes adds a view; it does not
add reach. If the RBAC had a bug, the blast radius was bounded by file permissions somebody else
already set.

Hosted, that backstop is gone. `FailureRepo._scope_sql` *is* the access control. A missing `AND`
clause is a cross-team data leak with nothing behind it.

This is why `tests/test_rbac.py` is written from the attacker's side and why `_scope_sql` and
`_visible` are checked against each other row by row for every role. Keep both. A second statement of
an access rule that nothing compares to the first is how the rule rots.

**What must change.** Nothing in the code — but the review posture does. Any change touching
`storage.FailureRepo`, `web/auth.py` or the scoping SQL is a security change and should be reviewed
as one.

### 1.3 The blast radius changes shape

| | CLI on a jump server | Hosted |
|---|---|---|
| Worst case if the app is compromised | What that one operator could already read | Everything anyone has ever uploaded |
| Who is exposed | One host, one account | Every account, every team |
| What an attacker needs | Access to the host | A network path to a public URL |
| What bounds it | The share's ACLs | Our own code |

`SECURITY.md`'s threat model was written for the left column. T1–T12 do not all carry over
unchanged, and at least one new entry is needed: **an internet-reachable service holding client
data**, which the original design did not have.

---

## 2. Where it must run instead

**Inside the client's own AWS account, in the same tenancy as Bedrock.**

The reasoning is `SECURITY.md` §12 and it is short: `bedrock` is chosen over `byok` because
inference runs inside the client's account rather than leaving for a third party. **Keeping Bedrock
for tenancy reasons while running the application that feeds it on a third-party PaaS discards the
argument being paid for.** The prompt content — the sanitized log, the code, possibly the screenshot
— passes through the application before it reaches Bedrock at all.

Railway is approved for **synthetic data only**. That is not a soft preference; it is the condition
under which hosting this was reasonable at all.

| Demo | Production |
|---|---|
| Railway, public URL | ECS Fargate or EKS in the client's account, private subnets |
| Railway PostgreSQL | RDS PostgreSQL, encrypted, private, automated backups |
| Public ingress | ALB behind the corporate network or VPN; no public ingress |
| Session cookie over Railway's TLS | The same, plus WAF and the client's egress controls |
| `EAGLE_EYES_SECRET_KEY` as a platform variable | Secrets Manager or Parameter Store, rotated |
| One container | At least two tasks behind the load balancer |

Two consequences of moving into the client's account that are easy to miss:

- **Bedrock's region must match the data-residency answer** (`SECURITY.md` Q9). Running the app in
  one region and Bedrock in another is a data transfer nobody signed off.
- **Egress.** The container needs a path to the Bedrock endpoint. `SECURITY.md` Q17 is blocking for
  the CLI and blocking here too — use a VPC endpoint for Bedrock rather than a NAT gateway and a
  hole in the allowlist.

---

## 3. Ingestion: the estate's shares are not reachable from a server

The demo's uploads exist because a hosted app has no share to scan. In a client estate the bot VMs'
`Network_Sharing_Folder` is reachable from the jump server and from nothing else, which is the point
of the jump server.

Three options, in the order I would argue for them:

**A. The CLI feeds a hosted API.** *Recommended.* The existing scanner keeps running where it runs
today, on a host that can already reach the shares, and posts sanitized results to the service. The
sanitizer runs before anything leaves the estate — the property `SECURITY.md` §4 depends on, kept
exactly as it is. The service never needs a route to a bot VM.

Needed: an authenticated ingest endpoint, a machine credential per scanner host, and the CLI taught
to post instead of only writing locally. The `Upload` shape in `web/ingest.py` is most of the
payload already.

**B. An on-prem pusher.** A small agent on the jump server watching the share and pushing. Same
security properties as A, one more thing to deploy and keep alive. Worth it only if the scan needs to
be continuous rather than scheduled.

**C. Give the service a route into the estate.** A VPN or Direct Connect so the container can mount
the shares. **I would not.** It turns the service into something with a network path to every bot VM,
which is exactly the reach the jump server exists to prevent — and it inverts §1.3: now a compromise
of the app reaches machines, not just stored data.

`pairing_method` is already `log_path` or `timestamp` rather than `uploaded` on the folder path:
the uploaded tree has the sibling directories, so discovery verifies the pairing instead of
asserting it, and refuses when two screenshots sit too close to the failure. What an on-prem
scanner adds is not better pairing but **reach** — the estate's shares, without anyone dropping a
folder into a browser — and a stable `code_mtime`, which is what the reuse gate needs
(`DATA_MODEL.md` §2.6) to serve a stored answer instead of paying for a repeat.

---

## 4. What is still missing for production

Honest list. Each of these is absent, not partial.

### 4.1 Screenshot cropping and redaction (modes 1 and 2)

`SECURITY.md` §3.3 designs four modes. **Two exist.** Mode 0 sends nothing; mode 3 sends the
screenshot exactly as captured — whole desktop, whatever was on screen. Modes 1 (crop to the failing
window) and 2 (crop, then OCR-redact) are drawings.

They were briefly selectable, and that was worse than not having them: choosing mode 2 sent the raw
image while the operator believed it had been cropped and scrubbed. `analysis.SCREENSHOT_MODES` is
now `{0, 3}` and anything else raises. **Do not re-admit a mode until the code behind it is written**
— the mode goes back into that set in the same change that implements it.

Until then a client wanting screenshots is choosing between "nothing" and "everything", and should be
told that in those words.

### 4.2 Language profiles beyond .NET and Selenium

The fingerprinter and the discovery regexes are tuned for C#/.NET/Selenium — the `--->` inner
exception chain, `at Namespace.Method() in File.cs:line N`, Selenium's `(Session info: chrome=…)`
trailer. `fingerprint.compute` takes a `profile` argument and only `dotnet` exists.

A Python, Java or JavaScript bot will still be ingested and still be analysed: the log goes to the
model as text. What degrades is **fingerprinting**, and therefore dedup, and therefore cost — the
normalisation that turns two hundred failures into one is language-specific. Expect the dedup rate to
fall well below the measured 90% on a non-.NET estate.

### 4.3 Providers beyond Anthropic

`model_gateway.py` is the only module that may import an SDK, and that boundary is enforced by
`tests/test_boundaries.py` rather than by convention — so adding a provider is genuinely one file.
But only Anthropic exists today, via Bedrock or a direct key. A client standardised on Azure OpenAI
or Vertex needs a new `Backend`, a new entry in `MODELS` and `PRICING`, and its own prompt
evaluation: the prompts in `eagle_eyes/prompts/` and the JSON schema they demand are tuned to one
model family.

### 4.4 Durable audit export

`audit_event` is append-only — triggers in both dialects, and in PostgreSQL a trigger rather than a
`REVOKE` because the application connects as the database owner and an owner cannot revoke from
itself. It is still **only in our database**. `SECURITY.md` Q13 asks whether audit must go to the
client's SIEM; if the answer is yes, that is a shipper and a format, and it is not written.

Retention is in the schema (`expires_at`) and applied by `run_retention`, which nothing schedules in
the hosted build. Q12 (is 7 years right?) is unanswered.

### 4.5 Disaster recovery

There is none. No backup policy, no restore procedure, no tested recovery. On RDS this is largely
configuration — automated backups, PITR, a restore rehearsal — but it is configuration nobody has
done, and an untested restore is not a backup.

### 4.6 Job durability

`web/jobs.py` is an in-process queue. A restart loses whatever is in flight, and the module says so
rather than pretending otherwise. For a demo that is honest; for production a request that was
charged for and then vanished is a real problem. Move to SQS, or a `job` table polled by workers —
the latter needs no new infrastructure and makes the queue visible in the same database as everything
else.

### 4.7 Password reset

Deliberately absent. An admin **cannot** set another account's password, because an admin who can do
that can act as any user and the audit log records it as that user. That leaves no reset path at all
today. Production needs one out-of-band — email a signed single-use token, or SSO, which removes the
question entirely (`SECURITY.md` Q14).

---

## 5. The open questions that gate real data

From `SECURITY.md` §9. These four block a hosted instance holding client data, and three of the four
are *harder* hosted than they were on the CLI.

| | Question | Why hosting changes it |
|---|---|---|
| **Q1** | May client-application screenshots ever be sent to a model? | On the CLI, Mode 0 made this deferrable — nothing was sent and nothing was copied, so the question could stay open while the pilot ran. An upload form moves the image before anyone answers. |
| **Q2** | Does cropped-and-redacted change the classification? | Unchanged in substance, but §4.1: there is no cropping and no redaction, so this cannot be answered with a demonstration. |
| **Q5** | Is leaving personal names unscrubbed in logs acceptable? | On the CLI, unscrubbed names sat in a database on one host, under that host's disk encryption. Hosted, they sit in a shared database reachable from the network, read by whoever our RBAC lets in. Same data, materially different exposure. |
| **Q8** | Do Bedrock's terms satisfy the client contract? | Now also: do the *hosting* terms? If the app runs in the client's account (§2) this reduces to the original question. If anyone proposes a third-party PaaS for real data, it is a second contract question and a harder one. |

And one that hosting creates, now added to `SECURITY.md` §9 so it sits with the rest rather than
only here — a blocking question that lives in a migration guide is one the security team never sees:

> **Q28 [BLOCKING for a hosted deployment]** Is an internet- or intranet-reachable service holding
> client-derived analyses acceptable at all, and under whose authorisation?

The CLI never had to ask. It read a share the operator could already reach, so it added a view
rather than reach. Q28 does not gate the CLI or the Phase 1 pilot; it gates this.

---

## 6. The checklist

Each demo shortcut, and what replaces it. In the order I would do them.

| # | Demo | Production | Why it matters |
|---|---|---|---|
| 1 | Railway | The client's AWS account, same tenancy as Bedrock | §2 — otherwise the tenancy argument is discarded |
| 2 | Public URL | Private subnets, ALB behind the corporate network or VPN | §1.3 — a network path to a public URL is not an acceptable prerequisite for reading client failures |
| 3 | Railway PostgreSQL | RDS, encrypted at rest, private, automated backups | §4.5 |
| 4 | `EAGLE_EYES_SECRET_KEY` as a platform variable | Secrets Manager, rotated | A leaked signing key mints sessions |
| 5 | `EAGLE_EYES_BACKEND=mock` or `byok` | `bedrock`, in the contracted region | `SECURITY.md` §12, Q8, Q9 |
| 6 | Web upload | CLI or pusher feeding an authenticated ingest API | §3 — sanitize before anything leaves the estate |
| 7 | Bootstrap admin from env vars | SSO, groups owned by the client's IdP | `SECURITY.md` Q14; also solves §4.7 |
| 8 | Synthetic fixtures seeded on boot | `EAGLE_EYES_SEED` unset. Never on a real deployment | Fabricated failures next to real ones is a reporting lie |
| 9 | Screenshot mode 0 or 3 | Mode 0 until §4.1 is built; then mode 1 with sign-off | Q1, Q2 |
| 10 | Audit in our database | Also shipped to the client's SIEM | Q13 |
| 11 | Retention unscheduled | `run_retention` on a schedule, with evidence it ran | Q12; a retention policy nobody applies is not a policy |
| 12 | In-process job queue | A `job` table or SQS | §4.6 |
| 13 | Spend caps via env vars | The same, plus a provider-side budget alarm | Two independent limits; ours can be misconfigured |
| 14 | One container | At least two tasks, health-checked | A single container is a single point of failure |
| 15 | No DR | Backups, a documented restore, a rehearsal | §4.5 |
| 16 | `dedup_rate` measured on .NET fixtures | Re-measure on the client's real mix | §4.2 — the cost model depends on this number |

**Items 1, 2, 6 and 8 are not optional and not sequencable.** Until all four are done, the instance
does not see client data at all.

---

## 7. What does *not* need to change

Worth stating, because a migration document that implies everything is provisional undersells what
is already load-bearing.

- **The engine.** `Engine.analyse` takes strings and bytes, touches no filesystem and calls no
  provider directly. It is the same code in the CLI, in the web app and in whatever comes next.
- **The sanitizer.** Protect-then-scrub, tested against a corpus seeded with the things it must
  catch, with a canary that fails the build if the scrubber silently stops working.
- **The fingerprinter.** The normalisation rules were derived by running them over realistic
  failures and watching the dedup rate move — the Chrome version trailer alone was a silent 3.3×
  cost multiplier.
- **The data model.** Written for PostgreSQL from the start (`DATA_MODEL.md` §8) and now ported and
  tested against a real server, with the whole RBAC suite running twice.
- **The access-control seams.** `Principal` is required by every repository; `_scope_sql` is the one
  place scoping happens. Both were in place before the web app existed, which is why adding one did
  not mean retrofitting authorisation.
- **The refusals.** Ambiguous screenshot pairing attaches nothing. An unparseable model response
  reports that the analysis did not complete, at zero confidence. Stale code caps confidence. A
  screenshot mode with no implementation raises. These are the product's character and they should
  survive every change above.
