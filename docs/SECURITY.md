# Eagle Eyes — Security Design

**This is the controlling document.** Where it conflicts with any other design doc, this one wins.
Where it conflicts with convenience, this one wins.

**Status:** proposal. Nothing here is approved. Section 9 is the list to take to EXL security.

---

## 1. Why this document is unusually cautious

The system ingests screenshots of live client applications. Those images contain, visibly,
whatever was on screen when the bot failed: customer names, policy numbers, account details,
addresses, claim histories. Unlike logs — where PII arrives in predictable fields we can pattern-
match — a screenshot is an unstructured raster. There is no schema. There is no reliable way to
know what is in it without reading it.

That asymmetry drives every decision below.

---

## 2. Threat model

Assets, ranked by damage on exposure:

1. **Screenshot images** — visible client PII, unstructured, high volume
2. **Execution logs** — PII in message strings and variable dumps
3. **Bot source code** — may embed credentials, connection strings, business logic
4. **Analyses** — derived, but quote log and code content back
5. **Audit logs** — reveal who investigated what

| # | Threat | Path | Likelihood | Impact | Primary control |
|---|---|---|---|---|---|
| T1 | Unredacted client PII sent to the model | Analysis worker submits raw image | Med | **Critical** | Mode gate; IAM separation; fail-closed redaction |
| T2 | Developer views another team's client data | Missing/weak authz on screenshot read | **High** | Critical | Data-layer authz; separate screenshot grant; adversarial tests |
| T3 | Credentials in code reach the model or logs | Code fetched and submitted unsanitized | High | High | Code scrubber; secret scanning in CI |
| T4 | Raw screenshot persists past policy | Lifecycle misconfiguration | Med | High | Bucket lifecycle + explicit delete + reconciliation job |
| T5 | Prompt injection via log or screenshot text | Attacker-controlled text reaches model | Low | Med | Delimited inputs; instruction-ignore directive; schema-validated output |
| T6 | Insider exports bulk analyses | Legitimate creds, illegitimate volume | Low | High | Rate limits; audit; anomaly alerting on bulk reads |
| T7 | PII leaks into our own application logs | Careless error logging | **High** | High | Structured logging with allowlisted fields only |
| T8 | Screenshot reaches a mailbox | Image embedded in notification | Med | High | Hard rule: notifications link, never embed |
| T9 | Quarantine bucket readable by wrong role | IAM drift | Low | Critical | Boot-time policy assertion; IaC; periodic check |
| **T10** | **The analyzer's service account can read every bot's logs and screenshots** | One credential with estate-wide share read | Med | **High** | Read-only; scoped to `Network_Sharing_Folder` only, never `C$`/`ADMIN$`; no write anywhere in the estate; credential held only on Exodus; usage audited |
| **T11** | **Exodus becomes a concentration point** | SQLite holds every sanitized log and analysis in one file | Med | High | Jump server's existing hardening and access controls; DB file ACL'd to the service account; short retention on log content |
| **T12** | **Path traversal out of the configured roots** | A crafted path or a bug reads arbitrary files over SMB | Low | High | Resolve every path and assert it stays under its configured root; refuse to start otherwise |

**The estate-wide threats from the previous draft are gone.** There is no agent on any bot VM, no
credential on hundreds of machines, and no second copy of any screenshot. Reading over existing SMB
shares from one host removed an entire class of risk that could not be fully mitigated.

**What replaces them is smaller but real, and concentrated.** T10 and T11 are the honest cost of a
single-host design: one service account that can read every bot's failure artifacts, and one database
holding every sanitized log and analysis. That account must be **read-only and scoped to the share
path** — not an admin share, not domain admin, and with no write access anywhere in the estate. A
broad *read* credential is still a valuable target, and it should be named as such in review rather
than presented as risk-free just because it is narrower than what came before.

**T2 and T7 deserve more attention than they usually get.** T1 is the threat everyone names first,
but it is a single well-guarded path. T2 is 150 developers using the system correctly every day
with authorization as the only thing standing between them and another client's data — a much
larger attack surface and a far likelier source of a real incident. T7 is the classic quiet
failure: PII scrubbed from the pipeline, then written to CloudWatch by an exception handler that
stringifies the whole payload.

---

## 3. Screenshot handling — the central decision

### 3.1 Options considered

**Option A — Never send screenshots to the model.** Store encrypted, show to authorized humans in
the UI, analyse on log + code only.

- *For:* eliminates T1 entirely. No OCR, no redaction, nothing to get wrong. Cheapest. Needs no
  new contractual position.
- *Against:* forfeits the capability that motivated the production upgrade. UI-interaction
  failures — selector not found, unexpected modal, application hung — are exactly the class a
  screenshot diagnoses and a log does not. We would be storing the most diagnostic input and
  refusing to use it.

**Option B — OCR, detect PII, mask, then send.** Textract or a local OCR engine extracts text with
bounding boxes; a PII detector (Comprehend, or rules) flags regions; those regions are drawn over
before submission.

- *For:* preserves most diagnostic value — layout, error dialogs, UI state survive masking.
- *Against:* **redaction is probabilistic and will sometimes fail.** OCR misses rotated, low-
  contrast, or unusually-rendered text. A PII detector cannot recognise a client-specific
  identifier format it has never seen. Residual leakage is not a hypothetical; it is the expected
  steady state at some non-zero rate. Anyone who tells you otherwise has not run OCR against
  production insurance screens. Adds per-image latency and cost.

**Option C — Crop to the error region only.** Send just the error dialog / exception popup.

- *For:* dramatic reduction in exposed surface — an error dialog is mostly application chrome. Far
  more predictable than Option B: we control precisely what is sent by geometry rather than by
  inference. Cheaper in tokens.
- *Against:* requires locating the error region, which is itself heuristic (topmost modal, focused
  window). Loses surrounding context that sometimes matters. An error dialog can itself contain a
  customer name ("Could not save record for J. Smith, policy 40192").

**Option C′ — iBot captures only the error region, at source.** Same as C, but the narrowing happens
inside iBot at capture time rather than server-side after upload.

- *For:* **strictly dominates C.** The surplus pixels are never written to disk at all, so they
  cannot be read by anyone — including us — and no derivative ever has to be created or deleted.
  iBot knows which window raised the error, so the region is *known* rather than heuristically
  inferred. Under Mode 0 this is an upstream improvement rather than a blocker; under Modes 1–2 it
  is what makes the derivative safe to create.
- *Against:* depends on the iBot team's roadmap, and only protects VMs running a new enough build —
  so the server-side control must exist regardless, as the fallback.
- **This option did not exist in the previous draft.** It is available only because iBot is
  in-house. It is the largest security improvement the platform decision unlocked.

**Option D — Send as captured, rely on platform terms.** Bedrock in-account, retention controls,
DPA.

- *For:* full fidelity, simplest pipeline.
- *Against:* moves the entire control from technical to contractual. Requires a client contractual
  position we do not currently have, and — importantly — it is not our decision to make.

**Option E — Structured extraction instead of an image.** Extract UI state (window titles, control
names, visible element tree) via the RPA tool's own accessibility APIs and send that text.

- *For:* structured means filterable. Much of a screenshot's diagnostic value is UI state, not
  pixels, and UI state can be scrubbed like a log.
- *Against:* only available if the RPA platform exposes it; varies by tool; not available for
  legacy/Citrix-rendered applications where the RPA tool sees only pixels — which are precisely
  the cases screenshots exist for.

### 3.2 Recommendation

**Ship in Mode 0 (Option A). Build the pipeline so Modes 1–3 are a config change. Pursue Mode 1 as
the first escalation, and pursue it as Option C′ — narrowing inside iBot — rather than Option C.**

Reasoning:

1. **Mode 0 needs no sign-off, so it cannot block Phase 1.** We get a production pilot running and
   real quality data while the security conversation proceeds in parallel. The screenshot is still
   captured, stored, and shown to the developer in the UI — so it still helps a human, which is
   most of its value today.

2. **Crop before redact, when we do escalate.** Option C/C′'s guarantee is geometric and auditable
   — "we sent these pixels and no others". Option B's guarantee is statistical — "our detector
   believed it found all the PII". A control you can verify by looking at it beats a control that
   depends on a model's recall. When someone asks "how do you know that image was clean?", C has an
   answer and B has a confidence interval.

   **And prefer narrowing at source (C′).** The best answer to "could the full screenshot leak?" is
   that a full screenshot was never captured. Because iBot is ours, that answer is available to us —
   it would not have been with a vendor tool. Put it on the iBot roadmap in Phase 0.

3. **Layer them rather than choosing.** The intended end state is crop *then* redact *then* submit:
   geometry narrows the surface, redaction cleans what survives, Bedrock keeps inference in-
   account. Defence in depth, where no single control failing is a breach.

4. **Fail closed, always.** If cropping cannot find an error region, or redaction errors, the image
   is not sent. Analysis proceeds text-only. There is no code path in which a failed control
   results in raw pixels reaching the model. This is the one rule in this document that must never
   acquire an exception.

**What I would defend to a VP and to the client:** we capture screenshots, encrypt them, tightly
control who can look at them, and today we do not send them to any model. When we propose to, we
will have iBot capture only the failing window rather than the whole desktop — so the surplus pixels
are never collected in the first place — redact what remains, and send it to an in-account endpoint,
with sign-off recorded.

**What I would not defend:** "the redaction model catches the PII." It mostly does. Mostly is not a
security control, and it is not what I want to be saying after an incident.

### 3.3 Mode mechanics

```
Mode 0  referenced in place, never copied, never sent    default; no sign-off needed
Mode 1  read → crop → derivative sent to model           security sign-off
Mode 2  read → crop → OCR-redact → derivative sent       security sign-off
Mode 3  read → sent to model as captured                 contract + DPA + named approver
```

**Mode 0 creates no copy of any screenshot.** The image is read only to record its path, size and
dimensions; the file stays on the bot VM share under the ACLs the estate already applies, and the
report links to it by UNC path. There is no bucket to secure, no lifecycle rule to verify, and no
deletion job to prove — because there is nothing to delete.

That is worth stating plainly in review: **the strongest control is not holding the data, and this
environment gives us that by default.** The question stops being "may we copy client screenshots into
cloud storage" and becomes "may we read a file that is already there, and send nothing."

Modes 1–3 reintroduce a derivative copy and are gated accordingly.

Binding rules:

- Mode is **global configuration**, never a per-request parameter. No API caller can elevate it.
- Mode changes are an audited config deployment with a recorded approver, not a runtime toggle.
- Mode 3 additionally requires a named approver recorded in config. It is included for
  completeness. I am not recommending it.
- **Every mode stores the original encrypted for human review.** Modes govern what reaches the
  *model*, not what the UI can show an authorized person.

---

## 4. Log and code sanitization

Carried forward from the POC scrubber and hardened. Runs **synchronously at ingest, before the
first durable write.**

### 4.1 Log scrubbing

Ordered rules, applied to every log line:

| Class | Action |
|---|---|
| Email addresses | `<EMAIL>` |
| Phone numbers (intl + local formats) | `<PHONE>` |
| National IDs (NI, SSN, Aadhaar, PAN) | `<NATID>` |
| Card numbers (Luhn-validated) | `<CARD>` |
| IBAN / sort code + account | `<BANK>` |
| Dates of birth in context | `<DOB>` |
| Postal addresses (heuristic) | `<ADDRESS>` |
| Client-specific ID formats | `<CLIENT_ID>` — **configurable per engagement, must be populated per client** |
| Bearer tokens, API keys, JWTs | `<SECRET>` |
| Connection strings | `<CONNSTR>` |
| Windows/UNC paths | basename kept, directory `<PATH>` |
| Person names | **not attempted** — see below |

**Two deliberate limitations, stated rather than hidden:**

*Names are not scrubbed.* Reliable name detection needs NER, which has poor precision on technical
logs and would mangle identifiers, class names, and method names that the analysis depends on. We
accept that names may survive in logs, and compensate with access control and retention rather
than pretending the scrubber catches them. **This must be an explicit question to security**
(§9 Q4), not a silent engineering choice.

*Client-specific ID formats must be configured per engagement.* A policy number format we have not
been told about will pass through. The scrubber's coverage is only as good as the configuration,
and shipping with an empty `<CLIENT_ID>` ruleset means that class is entirely unprotected.

### 4.2 Code scrubbing

- Hardcoded credentials, connection strings, API keys → `<REDACTED_SECRET>`
- Config file contents inlined in source → dropped
- Only the relevant file plus its direct imports are fetched, never the whole repository
- A configurable path denylist (credential stores, key material) is never fetched at all

### 4.3 Verification

Scrubber effectiveness is tested, not assumed:

- A corpus of real-shaped (synthetic) logs with known PII, asserted to zero residual
- Mutation tests: spacing, casing, delimiter, and unicode-homoglyph variants of each pattern
- A canary: seeded synthetic PII injected into a test failure must never appear in a stored
  analysis. Alerts if it does.

---

## 5. Data at rest

| Entity | Store | Encryption | Retention | Deletion |
|---|---|---|---|---|
| Screenshot (Mode 0) | **Not stored by us** — stays on the VM share | Estate's existing controls | Estate's existing policy | **Nothing to delete; we hold no copy** |
| Screenshot derivative (Modes 1–2 only) | Exodus local, dedicated dir | BitLocker / EFS | **7 days** | Retention job |
| Sanitized log | SQLite on Exodus | Volume encryption | 90 days | Retention job (nulls column, keeps row) |
| Code snapshot | SQLite on Exodus | Volume encryption | 90 days | Retention job |
| Analysis | SQLite on Exodus | Volume encryption | 12 months | Retention job |
| Fingerprint + metadata | SQLite on Exodus | Volume encryption | 24 months | Retention job |
| Feedback | SQLite on Exodus | Volume encryption | 24 months | — |
| Audit log | SQLite on Exodus, append-only | Volume encryption | **7 years** (proposed — §9 Q12) | Never by the app |
| HTML reports | Shared output folder | Share ACLs | 90 days | Retention job |

**The reports folder needs its own ACL review.** It is the one genuinely new place client-derived
content lands, it is readable by design so developers can use it without Exodus, and a permissive
share there would undo the access control in every other row of this table.

Notes:

- **We hold no screenshots at all in Mode 0.** The lowest-risk possible position, available because
  the images are already accessible where they sit.
- An analysis may outlive the screenshot it referenced, if the estate rotates the VM share. Reports
  must handle a dead link gracefully rather than implying the image was deleted by us.
- Fingerprints outlive log content — that is what makes long-window dedup possible without
  retaining the underlying PII.
- SMB reads are in-estate and should use SMB3 with encryption where the estate supports it.
- TLS 1.2+ for the Bedrock call and the SMTP relay.
- The SQLite file inherits Exodus's disk encryption; confirm the jump server actually has it.

---

## 6. Access control

### 6.1 Principles

- Authorization is enforced **at the data layer**, not at the route. Every repository read takes a
  caller identity. A route that forgets to check is still safe.
- **Viewing an analysis does not grant viewing its screenshot.** Two distinct permissions.
- Deny by default. An unevaluable authorization decision denies.

### 6.2 Roles

| Role | Analyses | Screenshots | Notes |
|---|---|---|---|
| Developer | Own bots' | Own bots' | Bot responsibility from the data model |
| Team lead | Team's bots | Team's bots | |
| Platform admin | All | **No** | Operates the system; does not need client data. Deliberate. |
| Security reviewer | All | All | Break-glass. Every access alerts. |
| Service accounts | Scoped | Policy worker only | Least privilege per task role |

**Platform admin cannot view screenshots.** This will be argued about. The argument to hold: the
person who keeps the system running has no operational need to see a customer's policy details,
and the number of people with standing access to client PII should be as close to zero as the job
allows.

### 6.3 Authentication

Organization SSO (Entra ID or Okta — §9 Q7). No local accounts. No API keys in the frontend.
Collector services use SigV4 / mTLS with per-collector identities, rotated.

### 6.4 Adversarial testing requirement

Authorization is tested by attempting to break it. The suite must include tests that try to read
another team's analysis, another team's screenshot, a screenshot with analysis-only permission, and
an expired screenshot — each asserting denial. A test suite that only proves the happy path proves
nothing about authorization.

---

## 7. Audit trail

Append-only. Written before the response is returned, not after.

Every one of these is logged: analysis read, **screenshot read** (separately and prominently), list
query with filters, feedback submission, config/mode change, retention deletion, break-glass use,
every authorization *denial*.

Each record: actor, actor role, action, resource, timestamp, source IP, request correlation ID,
outcome.

Denials are logged as carefully as successes — a burst of denials is the signature of both a
misconfiguration and a probe, and it is invisible if we only log what succeeded.

Alerting: bulk reads above threshold, any break-glass use, any mode change, denial-rate spikes.

---

## 8. Decisions that are not ours

The following require sign-off from EXL security, the client contract, or both. Engineering should
not settle any of them by choosing a default:

1. Whether client-application screenshots may be submitted to a model at all, in any form
2. Whether cropped-and-redacted counts as "not client data" or remains client data under contract
3. Retention periods for screenshots and analyses
4. Whether unscrubbed personal names in logs are acceptable given our other controls
5. Cross-border processing: which AWS region, and whether the client's contract constrains it
6. Whether Bedrock's data-handling terms satisfy the client's contract — **must be read, not assumed**
7. Whether analyses are client data subject to the same terms as the inputs
8. Whether the client must be notified that failure data is processed this way
9. Breach notification obligations and timelines specific to this engagement

---

## 9. Open questions for the security team

Take these as a list. Blocking ones are marked.

**Screenshots**
- **Q1 [BLOCKING]** May client-application screenshots ever be sent to a model? If conditionally, what conditions?
- **Q2 [BLOCKING]** If yes to Q1 — does cropped-and-redacted change the classification, or is it still client data?
- Q3 What retention is acceptable for stored screenshots? Is 30 days defensible, or should it be shorter?
- Q4 Who may view a stored screenshot? Does the developer responsible for the bot suffice, or is per-view approval required?

**Logs and code**
- **Q5 [BLOCKING]** Is leaving personal names unscrubbed in logs acceptable, given access control and retention? If not, we need a different approach and it will be lossy.
- Q6 Which client-specific identifier formats must the scrubber cover? We need actual formats, and the scrubber is materially incomplete without them.
- Q7 May bot source code be fetched by an automated service at all? Which repos are in scope?

**Exodus and the shares** *(internal — IT, security ops, and the iBot team)*
- **Q17 [BLOCKING]** May Exodus reach the Bedrock endpoint over outbound HTTPS? If not, who owns the allowlist? *Not a security question about data so much as the one that decides whether the system can exist.*
- **Q18** What scope may the analyzer's service account hold? Confirm **read-only, restricted to `Network_Sharing_Folder` and the code folder** — never `C$`/`ADMIN$`, never write. A broad read credential is still a target (T10).
- Q19 Is installing an application on Exodus acceptable, and what review does that require? Exodus is a control point into production, so this may be scrutinised harder than an ordinary host.
- Q20 Who may read the HTML reports share? This is the only new place client-derived content lands, and it is readable by design.
- Q21 Does Exodus have disk encryption enabled? The SQLite database relies on it.
- Q22 Are there bots whose screens must never be read at all, needing a per-bot exclusion list?
- Q23 Will iBot narrow screenshot capture to the failing window? *Still the best upstream improvement available, and now purely an efficiency and Mode 1/2 question rather than a Mode 0 blocker.*

**Platform and contract**
- **Q8 [BLOCKING]** Do Bedrock's data-handling terms satisfy the client contract for processing client-derived data? Who confirms this in writing?
- Q9 Which region must processing occur in? Any data-residency constraint?
- Q10 Is an analysis derived from client data itself client data, for retention and access purposes?
- Q11 Does the client need to be told, and by whom?

**Operations**
- Q12 What audit retention does compliance require? Is 7 years right?
- Q13 Must audit events go to an existing SIEM rather than our database?
- Q14 Which SSO provider, and who owns group membership that drives authorization?
- Q15 Is a penetration test required before pilot, and what is its lead time?
- Q16 What is the breach notification path if residual PII is found in a stored analysis?

**Answer Q17 before anything else** — it decides whether the analyzer can call a model from Exodus
at all. Then Q5 and Q8 before Phase 1 code, and Q1/Q2 before Phase 2.

Note what moved: Q1 and Q2 (may screenshots reach a model) no longer gate Phase 1 in any way, because
Mode 0 now sends nothing *and copies nothing*. They gate only the vision capability in Phase 2. The rest can resolve during Phase 1 —
Mode 0 is safe while they are open, which is the point of shipping in it.

---

## 10. Security-for-convenience tradeoffs, stated explicitly

The kit asked that these be called out rather than buried. In full:

1. **In Modes 1–2 a screenshot derivative is created on Exodus** rather than being narrowed on the
   bot VM. Bought: one maintainable implementation instead of an estate-wide change. Cost: a
   short-lived second copy of client pixels on the jump server. **Mode 0 has no such tradeoff — it
   creates no copy at all.**

2. **Personal names are not scrubbed from logs.** Bought: a scrubber that does not corrupt the
   technical content analysis depends on. Cost: names may persist in stored logs for 90 days.

3. **Analyses quote log and code content back.** Bought: diagnoses a developer can act on. Cost:
   sanitized-but-real content is duplicated into a longer-retained entity.

4. **Dedup reuses an analysis across bots and teams.** Bought: the primary cost control. Cost: an
   analysis generated from Team A's failure can be shown to Team B. Mitigation: only the diagnosis
   text is reused, never the original log excerpt or screenshot — the reusing team sees the
   conclusion, not the source data. **This mitigation is load-bearing and must be enforced in the
   data layer** (see `DATA_MODEL.md` §5).

5. **Platform admins can see failure metadata** (bot, error type, frequency) without client data
   access. Bought: operability. Cost: metadata is not nothing — failure patterns leak some
   information about client operations.

6. **The analyzer runs only while Exodus is logged in.** Bought: no always-on host to harden, patch
   and monitor. Cost: overnight failures wait for the next session. Not a security issue; recorded
   because it shapes what the pilot can promise.

7. **One service account can read every bot's logs and screenshots.** Bought: no software and no
   credential on any bot VM, and no second copy of any image. Cost: a single broad *read* credential
   (T10). Mitigation: read-only, share-scoped, no write, held only on Exodus, usage audited. Far
   better than the per-VM agent it replaces, but not nothing — say so in review.

8. **Every analysis and sanitized log sits in one SQLite file on Exodus.** Bought: no database
   server, no backup agent, no DBA, and data that never leaves the estate except as a model prompt.
   Cost: a concentration point (T11) whose protection is entirely the jump server's existing
   hardening.

9. **HTML reports land on a share readable without Exodus.** Bought: 150 developers get value without
   logging into a jump server — the "no change to how they work" requirement. Cost: the one new
   location holding client-derived content, and the easiest thing in this design to misconfigure.

10. **Analyses may reason about code the bot was not running.** Bought: code input at all, given iBot
    has only a copy function and no version control. Cost: a real correctness risk, mitigated by the
    mtime staleness flag and confidence cap (`ARCHITECTURE.md` §4.5) rather than solved.
