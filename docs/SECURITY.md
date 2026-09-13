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

**Ship in Mode 0 (Option A). Build the pipeline so Modes 1–3 are a config change. Pursue Mode 1
(Option C, crop) as the first escalation, not Mode 2.**

Reasoning:

1. **Mode 0 needs no sign-off, so it cannot block Phase 1.** We get a production pilot running and
   real quality data while the security conversation proceeds in parallel. The screenshot is still
   captured, stored, and shown to the developer in the UI — so it still helps a human, which is
   most of its value today.

2. **Crop before redact, when we do escalate.** Option C's guarantee is geometric and auditable —
   "we sent these pixels and no others". Option B's guarantee is statistical — "our detector
   believed it found all the PII". A control you can verify by looking at it beats a control that
   depends on a model's recall. When someone asks "how do you know that image was clean?", Option C
   has an answer and Option B has a confidence interval.

3. **Layer them rather than choosing.** The intended end state is crop *then* redact *then* submit:
   geometry narrows the surface, redaction cleans what survives, Bedrock keeps inference in-
   account. Defence in depth, where no single control failing is a breach.

4. **Fail closed, always.** If cropping cannot find an error region, or redaction errors, the image
   is not sent. Analysis proceeds text-only. There is no code path in which a failed control
   results in raw pixels reaching the model. This is the one rule in this document that must never
   acquire an exception.

**What I would defend to a VP and to the client:** we capture screenshots, encrypt them, tightly
control who can look at them, and today we do not send them to any model. When we propose to, we
will send a cropped region rather than a full screen, redacted, to an in-account endpoint, with
sign-off recorded.

**What I would not defend:** "the redaction model catches the PII." It mostly does. Mostly is not a
security control, and it is not what I want to be saying after an incident.

### 3.3 Mode mechanics

```
Mode 0  quarantine → artifacts (encrypted, no model)        default; no sign-off needed
Mode 1  quarantine → crop → artifacts + model               security sign-off
Mode 2  quarantine → crop → OCR-redact → artifacts + model  security sign-off
Mode 3  quarantine → artifacts + model, as captured         contract + DPA + named approver
```

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
| Raw screenshot | S3 quarantine | SSE-KMS, dedicated CMK | **24 hours hard max** | Explicit delete after processing + lifecycle backstop |
| Processed screenshot | S3 artifacts | SSE-KMS | **30 days** (proposed — §9 Q1) | Retention job |
| Sanitized log | Postgres | Encrypted at rest (KMS) | 90 days | Retention job |
| Code snapshot | Postgres | Encrypted at rest | 90 days | Retention job |
| Analysis | Postgres | Encrypted at rest | 12 months | Retention job |
| Fingerprint + metadata | Postgres | Encrypted at rest | 24 months | — |
| Feedback | Postgres | Encrypted at rest | 24 months | — |
| Audit log | Postgres, append-only | Encrypted at rest | **7 years** (proposed — §9 Q2) | Never by the app |

Notes:

- **Screenshots have the shortest retention of any artifact.** Deliberate: highest risk, lowest
  long-term value. Once the analysis exists, the image has served its purpose.
- Analyses outlive their screenshots. An analysis older than 30 days shows "screenshot expired".
- Fingerprints outlive log content — that is what makes long-window dedup possible without
  retaining the underlying PII.
- Separate CMK for the quarantine bucket, so key-policy denial is an independent second control
  after bucket policy.
- TLS 1.2+ everywhere in transit. No plaintext hop, including inside the VPC.

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

**Answer Q1, Q2, Q5, and Q8 before Phase 2 begins.** The rest can resolve during Phase 1 —
Mode 0 is safe while they are open, which is the point of shipping in it.

---

## 10. Security-for-convenience tradeoffs, stated explicitly

The kit asked that these be called out rather than buried. In full:

1. **Raw screenshots transit the network and rest briefly in S3** rather than being redacted on the
   bot VM. Bought: one maintainable redaction implementation instead of an estate-wide rollout.
   Cost: a 24-hour window in which raw pixels exist in our account.

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

6. **Standard SQS, at-least-once delivery.** Bought: simplicity. Cost: an analysis may occasionally
   be computed twice. Not a security issue, noted for completeness.
