# Eagle Eyes — Delivery Roadmap

Effort in **person-weeks**. You are product owner and contribute to the AI logic; you are not the
sole engineer. Roles: **BE** backend, **FE** frontend, **DevOps/Cloud**, **Sec** security
reviewer (part-time), **PO** you.

---

## Phase 0 — Decisions and access (no code)

**Goal:** remove the unknowns that would force rework later.

| Work | Owner | Effort |
|---|---|---|
| Take `SECURITY.md` §9 to EXL security; get Q1, Q2, Q5, Q8 answered | PO | — |
| Confirm Bedrock data-handling terms against the client contract, in writing | PO + Sec | — |
| **Confirm Bedrock reachability** — `tools/check_bedrock.py`, on a dev account now and on Exodus when access lands | BE + DevOps | 0.1 |
| **Stand up the local sandbox** — `tools/make_fixtures.py`, real Bedrock against synthetic data. Unblocked today; needs no sign-off. | BE | 0.2 |
| **Get one real directory listing** from a VM share date folder + one sanitized sample log | PO | 0.1 |
| **Confirm the log↔screenshot pairing convention** from that sample (run ID? filename? timestamp only?) | PO + iBot team | — |
| Confirm the code folder's naming convention and how `bot_number` maps to a file | PO | — |
| Service account with read-only access to the VM shares and code folder | IT / Identity | 0.5 |
| Approval to install an application on Exodus | Security + IT | — |
| **Open the iBot conversation:** capture narrowing, structured error metadata | PO + iBot team | — |
| AWS account, VPC, Bedrock model access enabled in-region | DevOps | 0.5 |
| Confirm SSO provider and the group structure driving authorization | PO + IT | — |
| Identify 5–8 pilot bots and 5–8 pilot developers | PO | — |
| **Capture the pre-system baseline** (see Phase 1) | PO | 0.5 |

**Elapsed:** 2–4 weeks, mostly waiting on other people. Engineering effort ~1 week.

**Dependencies:** EXL security, client contract owner, IT/cloud/network, iBot team, RPA ops.

**Exit:** Q17 (Exodus → Bedrock egress) confirmed; Q5 and Q8 answered; pilot bots named; a real
directory listing in hand so pairing is settled; service account created; baseline captured.

> **Two of these are an afternoon each and both are blocking.** One command from Exodus settles
> whether the analyzer can call a model at all. One directory listing settles whether screenshots
> can be attached to the right failure. Neither needs a meeting, and everything downstream assumes
> both. Do them first.

> **Phase 0 does not block Phase 1.** Mode 0 (`SECURITY.md` §3.3) is safe with every screenshot
> question still open — that is what it is for. Start Phase 1 in parallel; only Phase 3 truly
> depends on the answers.

---

## Phase 1 — Narrow pilot, production-grade

**Goal:** 5–8 bots, 5–8 developers, real failures, real feedback. Production quality at small
scale — not a prototype with a pilot label.

### Scope

**In:**
- **Scanner: tree walk, watermark, path parsing, catch-up on start**
- **Correlator: log ↔ screenshot ↔ code pairing, with explicit refusal when ambiguous**
- **Selection and review: folder/file pickers, a table the user can change before anything is sent,
  and per-row overrides for screenshot, code and re-analysis**
- Ingestion, sanitization, fingerprinting, dedup
- Triage (Haiku 4.5) + deep text analysis (Sonnet 5)
- **Screenshots captured, encrypted, stored, viewable in UI — Mode 0, not sent to any model**
- SQLite storage on Exodus
- Email notification with suppression, via the internal relay
- HTML report per failure, written to a shared folder
- Audit logging, retention job
- Structured logging, metrics, budget guard

**Out:** vision analysis, Teams integration, web UI, operations dashboard, digest mode, automated
pattern learning, any always-on service.

### Effort

| Workstream | Roles | Weeks |
|---|---|---|
| Repository foundation, CI, secret scanning | BE | 1 |
| Data layer (SQLite), migrations, fingerprint + tests | BE | 1.5 |
| **Scanner + watermark + catch-up** | BE | 1.5 |
| **Correlator (log ↔ screenshot ↔ code), with ambiguity refusal** | BE | 1 |
| **Selection, review table and overrides** | BE | 1 |
| Sanitization + dedup | BE | 1.5 |
| Analysis engine, `model_gateway`, prompts | BE + PO | 2.5 |
| Notifications + HTML reports | BE | 1.5 |
| Audit, retention, budget guard | BE | 1 |
| Packaging + install on Exodus, scheduling | BE + DevOps | 1 |
| Security review + hardening | Sec + BE | 1.5 |
| Pilot onboarding, runbook, docs | PO + BE | 1 |

**Total ~15.5 person-weeks.** With 2 BE + 0.25 DevOps + 0.25 Sec: **6–8 calendar weeks.** No
frontend needed in Phase 1.

Down from ~20 in the previous draft. Reading existing shares from one host deleted the emitter
fleet, the ingestion API, the AWS infrastructure work, SSO, and the web UI — replacing all of it with
a scanner and a correlator.

**The riskiest item is now the correlator**, not deployment. If log↔screenshot pairing turns out to
rest on timestamp proximity, the screenshot input is unreliable for concurrent failures and we will
be refusing to attach images more often than we would like. That is a correctness problem, and it is
why the directory listing is a Phase 0 exit condition rather than a Phase 1 discovery.

This is "weeks, not months" only with that team. With one engineer it is four to five months, and
the pilot should be cut harder rather than run that long — drop notifications and the UI feed, and
deliver analyses by email alone.

### Unlocks

Real accuracy data. Real dedup hit rate against real logs. Real cost against projections. A working
system to point at while the screenshot question resolves — and, because Mode 0 copies nothing, one
that needs no screenshot sign-off to run at all.

---

## Phase 2 — Vision, gated on security

**Goal:** turn on the capability that motivated production, if and only if security permits.

**Blocked on:** `SECURITY.md` Q1 and Q2. Do not start until answered.

### Scope

- Screenshot policy worker: crop (Mode 1), then OCR-redact (Mode 2)
- Vision escalation gate in triage
- Vision analysis path in `model_gateway`
- Redaction quality test harness with a seeded-PII canary corpus
- UI redaction indicator
- Image token cost logging validated against `COST_MODEL.md` §2

| Workstream | Roles | Weeks |
|---|---|---|
| Policy worker, crop + redact, fail-closed | BE | 2.5 |
| Redaction test harness and canary corpus | BE + Sec | 1.5 |
| Vision gate + analysis path | BE + PO | 1.5 |
| UI changes | FE | 0.5 |
| Security re-review of the screenshot path | Sec | 1 |

**Total ~7 person-weeks → 3–4 calendar weeks.**

**If security answers "no" to Q1, this phase does not happen.** Its budget moves to Phase 3. That
is a legitimate outcome, not a failure — and it is why Phase 1 does not depend on it.

---

## Phase 3 — Scale to the estate

**Goal:** 150 developers, all pilot-validated bot categories — and getting off the jump server.

The Exodus deployment is deliberately a Phase 1 shortcut. It is bound to an interactive session, so
overnight failures wait for someone to log in, and it does not serve a web UI to anyone who is not on
the jump server. Phase 3 moves the same code to a host that stays up. The catch-up scan built in
Phase 1 (`ARCHITECTURE.md` §4.3) is what makes that a change of trigger rather than a rewrite.

### Scope

- Teams/Slack integration
- Operations dashboard
- Digest mode and per-developer rate caps
- Pattern library seeded from Phase 1 data
- Load test at spike scale (500 failures in 2 minutes)
- Autoscaling tuned on real load

| Workstream | Roles | Weeks |
|---|---|---|
| **Move off Exodus to an always-on host; port SQLite → Postgres** | BE + DevOps | 3 |
| **Web UI + SSO** (needs a host that stays up) | FE + BE | 3 |
| Chat integration | BE | 1 |
| Operations dashboard | FE + BE | 2.5 |
| Digest + rate caps | BE | 1 |
| Pattern library from real data | PO + BE | 1.5 |
| Load testing and scaling | DevOps + BE | 1.5 |
| Onboarding at scale | PO | 1 |

**Total ~13–16 person-weeks → 6–8 calendar weeks.**

**Gate:** do not enter Phase 3 without Phase 1 evidence (§ *Go/no-go* below). Rolling a system
developers do not trust out to 150 people converts a small problem into an organization-wide one.

---

## Phase 4 — Learning loop

**Goal:** the system improves from feedback instead of staying static.

- Feedback-driven prompt iteration with an eval set built from labelled Phase 1–3 failures
- Automatic pattern promotion: a fingerprint recurring with consistent `correct` feedback becomes
  a template, dropping to zero model cost
- Accuracy trend reporting per failure category
- Regression eval gating prompt changes in CI

**~6 person-weeks.** Ongoing thereafter.

This is where feedback collected from Phase 1 finally pays off. Building the feedback endpoint in
Phase 1 with nothing consuming it is deliberate — the data has to exist before the loop can.

---

## Dependency map

| Dependency | Needed by | Owner | Risk if late |
|---|---|---|---|
| **Exodus → Bedrock outbound HTTPS** | **Phase 1** | Network / IT | **No model call possible. Hard blocker — one command settles it.** |
| **Read-only service account for VM shares + code folder** | **Phase 1** | IT / Identity | Analyzer cannot read anything |
| **Approval to install on Exodus** | **Phase 1** | Security + IT | No deployment target |
| **Log↔screenshot pairing convention** | **Phase 1** | iBot team (internal) | Screenshots attach to the wrong failure, or must be dropped |
| Code folder naming convention | Phase 1 | PO / RPA ops | Code input unavailable; log-only analysis |
| SMTP relay accepts mail from Exodus | Phase 1 | IT | Reports only, no notifications |
| Shared folder for HTML reports, with ACLs | Phase 1 | IT | Developers need Exodus to see results — defeats the purpose |
| iBot: structured error metadata | Phase 1 quality | iBot team (internal) | Fingerprint stays regex-based and fragile |
| iBot: capture narrowing | Phase 2 | iBot team (internal) | Falls back to reading full screenshots for Modes 1–2 |
| Security answers Q1, Q2 | Phase 2 | EXL Security | Phase 2 slips; Phase 1 unaffected |
| Security answers Q5, Q8 | **Phase 1** | EXL Security + contract | **Blocks Phase 1** |
| Client-specific PII formats (Q6) | Phase 1 | Client / engagement lead | Scrubber ships incomplete |
| AWS account + Bedrock access | Phase 1 | IT / Cloud | Blocks all development |
| SSO app registration | Phase 1 API | IT / Identity | API ships without auth — unacceptable, would block pilot |
| Repo read access for bot code | Phase 1 | iBot team / RPA ops | Degrades to log-only analysis, or code ships in the envelope |
| Mail relay / SES approval | Phase 1 notify | IT | Dry-run mode only |
| Pilot bot + developer selection | Phase 1 | PO | Blocks pilot start |
| Client notification (Q11) | Pilot go-live | Contract owner | Legal exposure |
| Penetration test (Q15) | Phase 3 | Security | Blocks estate rollout |

**The critical path runs through IT, not Security.** Every blocker above is an access or permission
question: egress from Exodus, a service account, permission to install, a share for reports. None is
a design question, and none can be worked around.

The compensating gain is large: because Mode 0 copies no screenshots and stores nothing outside the
estate, **the screenshot sign-off no longer gates Phase 1 at all.** The security conversation that
looked like the critical path two drafts ago now gates only the vision capability in Phase 2.

The compensating gain: several things that would have been vendor constraints are now internal
roadmap items with a colleague's name on them (`ARCHITECTURE.md` §3). Push on them early — the
iBot team needs lead time, and capture narrowing in particular is the best security improvement
available to this project.

**Q5 and Q8 remain the two security answers that can stop Phase 1.** Q5 (unscrubbed names in logs) and Q8 (do Bedrock
terms satisfy the contract) affect text processing, which Mode 0 does not avoid. Chase these two
first — they are on the critical path in a way the screenshot questions are not.

---

## Timeline

```
Week:   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17
P0    [=======]
P1        [===========================]
P2                              [========]        (if Q1 = yes)
P3                                      [============]
P4                                                  [==========]
```

Assumes the team above. **The dominant schedule risk is IT turnaround on access — egress, service
account, install approval — not engineering and no longer security.** Phase 0 starting on day one is the highest-leverage
thing available.

---

## Go/no-go before Phase 3

Do not scale without all of:

| Criterion | Bar |
|---|---|
| Analysis accuracy | ≥70% `correct` or `partial` on ≥50 rated analyses |
| Confident-wrong rate | <10% of high-confidence analyses rated `wrong` |
| Dedup hit rate | ≥50% after four weeks |
| False-merge rate | <5% on the sampling audit (`DATA_MODEL.md` §2.7) |
| Cost | Within 2× of `COST_MODEL.md` projection |
| Security | No unresolved critical finding |
| Trust | Majority of pilot developers say they would keep using it |

**The confident-wrong rate is the one that should stop a rollout.** A system that is often unsure is
survivable; a system that is confidently wrong 20% of the time destroys trust permanently and will
not get a second chance with these developers.
