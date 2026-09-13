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
| **Confirm bot VMs can reach an AWS endpoint over outbound HTTPS** — proxy, TLS inspection, firewall | DevOps + Network | 0.5 |
| **Check for an existing approved agent on bot VMs** (CloudWatch, Fluent Bit, Splunk, SCCM) to extend instead of deploying ours | DevOps + IT | 0.5 |
| **Open the iBot conversation:** capture narrowing, structured error metadata, native event POST | PO + iBot team | — |
| Get iBot's log format, screenshot naming, and log↔screenshot correlation convention documented | PO + iBot team | — |
| AWS account, VPC, Bedrock model access enabled in-region | DevOps | 0.5 |
| Confirm SSO provider and the group structure driving authorization | PO + IT | — |
| Identify 5–8 pilot bots and 5–8 pilot developers | PO | — |
| **Capture the pre-system baseline** (see Phase 1) | PO | 0.5 |

**Elapsed:** 2–4 weeks, mostly waiting on other people. Engineering effort ~1 week.

**Dependencies:** EXL security, client contract owner, IT/cloud/network, iBot team, RPA ops.

**Exit:** Q1/Q2/Q5/Q8/Q18 answered; pilot bots named; AWS account with Bedrock access; baseline
captured; **a confirmed network path from a bot VM to our endpoint**; iBot asks logged on their
backlog with an owner.

> **The network path is the new hard blocker.** iBot writes only to local disk, so if bot VMs cannot
> reach our ingestion endpoint there is no ingestion path and no amount of design works around it.
> Prove it with one VM and one curl in week one, before anything else is built.

> **Phase 0 does not block Phase 1.** Mode 0 (`SECURITY.md` §3.3) is safe with every screenshot
> question still open — that is what it is for. Start Phase 1 in parallel; only Phase 3 truly
> depends on the answers.

---

## Phase 1 — Narrow pilot, production-grade

**Goal:** 5–8 bots, 5–8 developers, real failures, real feedback. Production quality at small
scale — not a prototype with a pilot label.

### Scope

**In:**
- **Emitter (Option B sidecar): spool, backoff, resource ceiling, packaging, deployment** — the
  largest new piece of work and the one with the least precedent
- Ingestion, sanitization, fingerprinting, dedup
- Triage (Haiku 4.5) + deep text analysis (Sonnet 5)
- **Screenshots captured, encrypted, stored, viewable in UI — Mode 0, not sent to any model**
- Postgres, S3, SQS, ECS on AWS
- Service API with SSO and data-layer authorization
- Email notification with suppression
- Failure feed + analysis detail UI, with feedback controls
- Audit logging, retention job
- Structured logging, metrics, budget guard

**Out:** vision analysis, Teams integration, operations dashboard, digest mode, automated pattern
learning, Option A (iBot-native emission — tracked in parallel, not depended on).

### Effort

| Workstream | Roles | Weeks |
|---|---|---|
| Repository foundation, CI, secret scanning | BE + DevOps | 1 |
| Data layer, migrations, fingerprint + tests | BE | 2 |
| Ingestion API, sanitization, dedup | BE | 2 |
| **Emitter: spool, retry, packaging, deployment, soak test on a real bot VM** | BE + DevOps | **3** |
| Analysis engine, `model_gateway`, prompts | BE + PO | 2.5 |
| API, SSO, authorization, audit | BE | 2 |
| Notifications with suppression | BE | 1 |
| UI — two views | FE | 2.5 |
| AWS infrastructure as code, deployment | DevOps | 2 |
| Security review + hardening | Sec + BE | 1.5 |
| Pilot onboarding, runbook, docs | PO + BE | 1 |

**Total ~20 person-weeks.** With 2 BE + 1 FE + 0.5 DevOps + 0.25 Sec: **8–10 calendar weeks.**

Two weeks more than the multi-platform draft, and the shape of the risk has moved. Dropping to one
platform saved adapter work; pushing from VMs cost more than that back. The emitter is the riskiest
item in Phase 1 — it runs on production machines we do not own, its failure modes are remote and
quiet, and every release goes through change control.

This is "weeks, not months" only with that team. With one engineer it is four to five months, and
the pilot should be cut harder rather than run that long — drop notifications and the UI feed, and
deliver analyses by email alone.

### Unlocks

Real accuracy data. Real dedup hit rate against real logs. Real cost against §8 projections. A
working system to point at while the screenshot question resolves.

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

**Goal:** 150 developers, all pilot-validated bot categories.

### Scope

- Teams/Slack integration
- Operations dashboard
- Digest mode and per-developer rate caps
- Pattern library seeded from Phase 1 data
- Load test at spike scale (500 failures in 2 minutes)
- Autoscaling tuned on real load

| Workstream | Roles | Weeks |
|---|---|---|
| **Emitter rollout to the full estate** (staged rings, monitoring, rollback) | DevOps + BE | 2 |
| **Migrate to Option A** if iBot ships native emission | BE + iBot team | 1 |
| Chat integration | BE | 1 |
| Operations dashboard | FE + BE | 2.5 |
| Digest + rate caps | BE | 1 |
| Pattern library from real data | PO + BE | 1.5 |
| Load testing and scaling | DevOps + BE | 1.5 |
| Onboarding at scale | PO | 1 |

**Total ~11–14 person-weeks → 5–7 calendar weeks.**

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
| **Network path: bot VM → AWS endpoint** | **Phase 1** | Network / IT | **No ingestion path at all. Hard blocker — prove it in week one.** |
| **Approval to deploy the emitter estate-wide** | **Phase 1** | Security + IT | Forces dependence on iBot's release cycle for Option A |
| **iBot: log format + correlation convention** | Phase 1 | iBot team (internal) | Emitter cannot correlate log to screenshot reliably |
| iBot: structured error metadata | Phase 1 quality | iBot team (internal) | Fingerprint stays regex-based and fragile |
| iBot: capture narrowing (Option C′) | Phase 2 | iBot team (internal) | Falls back to server-side crop — weaker, still workable |
| Software deployment mechanism to bot VMs | Phase 1 | IT / RPA ops | Every emitter release becomes slow and manual |
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

**The dependency profile changed with iBot.** Previously the critical path ran through EXL Security.
It now runs through **IT and Network** — the path from a bot VM to our endpoint, and permission to
put software on production VMs. Neither is a design question and neither can be worked around;
both should be settled in week one.

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

Assumes the team above and that Q5/Q8 answer inside three weeks. **The dominant schedule risks are
now network/IT approval and emitter rollout, with security response close behind.** Phase 0 starting on day one is the highest-leverage
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
