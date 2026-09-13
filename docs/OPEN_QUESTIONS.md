# Eagle Eyes — Open Questions

Everything the design assumed. The brief asked to be aggressive here, so this is deliberately long.

**Marking:** 🔴 blocking (answer before Phase 2 code) · 🟡 needed during Phase 1 · ⚪ can wait.

Each question states **the assumption I made**, so that if nobody answers, you can at least see
what you inherited.

---

## A. Security and compliance

| # | Question | Assumed | Ask |
|---|---|---|---|
| 🔴 A1 | May client-application screenshots ever be sent to a model? | **No** — ship Mode 0 | EXL Security |
| 🔴 A2 | Does cropping + redaction change the data's classification, or is it still client data? | Still client data | Security + contract |
| 🔴 A3 | Is leaving personal names unscrubbed in logs acceptable? | Yes, given access control + 90-day retention | Security |
| 🔴 A4 | Do Bedrock's data-handling terms satisfy the client contract? | Assumed yes — **unverified, must be read** | Contract owner |
| 🟡 A5 | Which client-specific ID formats must the scrubber cover? | None configured — **scrubber is materially incomplete without this** | Engagement lead |
| 🟡 A6 | Screenshot retention — is 30 days defensible? | 30 days | Security |
| 🟡 A7 | Analysis retention — 12 months? | 12 months | Security |
| 🟡 A8 | Audit retention — 7 years? | 7 years | Compliance |
| 🟡 A9 | Is an analysis derived from client data itself client data? | Yes, treated as such | Legal |
| 🟡 A10 | Must the client be told failure data is processed this way? Who tells them? | Assumed yes, PO raises it | Contract owner |
| 🟡 A11 | Data residency — which region must processing occur in? | `eu-west-1` | Security + contract |
| ⚪ A12 | Penetration test required before estate rollout? Lead time? | Yes, before Phase 3 | Security |
| ⚪ A13 | Breach path if residual PII is found in a stored analysis? | Standard EXL IR process | Security |
| ⚪ A14 | Does a DPIA exist or is one needed? | Needed | Privacy/DPO |
| ⚪ A15 | Is Mode 3 (raw screenshots to model) categorically off the table? | Yes — not recommended | Security |

---

## B. Infrastructure and IT

| # | Question | Assumed | Ask |
|---|---|---|---|
| 🔴 B1 | Is an AWS account available with Bedrock enabled in the target region? | Yes | Cloud/IT |
| 🔴 B2 | Which SSO provider, and who owns the groups driving authorization? | Entra ID, team-mapped groups | IT/Identity |
| 🔴 B3 | **Can bot VMs reach an AWS endpoint over outbound HTTPS?** Proxy? TLS inspection? | Yes, via corporate proxy — **unverified, and if no there is no ingestion path** | Network / IT |
| 🔴 B4 | **May we deploy the emitter to production bot VMs?** What review does estate-wide software need? | Yes with change control | Security + IT |
| 🔴 B5 | **Is an approved agent already on these VMs** (CloudWatch, Fluent Bit, Splunk, SCCM) we could extend? | No — **checking this first could remove the largest piece of Phase 1 risk** | DevOps / IT |
| 🟡 B5a | How is software deployed and updated on bot VMs? Change-control lead time? | SCCM-style push, weeks per release | IT / RPA ops |
| 🟡 B5b | What CPU/memory headroom exists on a bot VM? | Enough for a small agent — **must be confirmed; the emitter shares a VM with production work** | RPA ops |
| 🟡 B3a | Where does iBot bot source live — version control, central store, or only on the VM? | In git — if actually on-VM, code ships in the envelope instead | iBot team |
| 🟡 B6 | Mail relay — SES, or an internal relay? Approval needed? | SES with verified domain | IT |
| 🟡 B7 | Teams or Slack? Can we register an app/webhook? | Teams, Phase 3 | IT |
| 🟡 B8 | Is there an existing SIEM that must receive audit events? | No — audit in Postgres | Security ops |
| ⚪ B9 | Existing observability platform (Datadog, Dynatrace) we should use over CloudWatch? | CloudWatch | Platform eng |
| ⚪ B10 | Network path from bot VMs to AWS — direct, or via proxy/Direct Connect? | HTTPS via corporate proxy | Network |
| ⚪ B11 | Who operates this after delivery? Which on-call rota? | Undecided — **this needs an owner before go-live** | Engineering management |
| ⚪ B12 | DR expectations — RPO/RTO? | RPO 24h, RTO 4h, not agreed | Platform eng |

---

## C. Product scope

| # | Question | Assumed | Ask |
|---|---|---|---|
| ⚪ C1 | ~~Which RPA platform?~~ **Settled: iBot only.** No adapter framework is built. | — | — |
| 🟡 C2 | Which 5–8 bots, and which 5–8 developers? | Not selected | PO |
| 🟡 C3 | What is the current MTTR baseline? **Has it ever been measured?** | Unknown — **must be captured before go-live or no improvement can be claimed** | PO |
| 🟡 C4 | Does "bot ownership" exist as data in iBot, or is it tribal knowledge? | Exists and is accurate — **frequently false in practice; routing depends on it** | iBot team / RPA ops |
| 🟡 C5 | What are the actual top failure categories? Needed to seed templates. | Selector failures, credential expiry, file/IO, timeouts | Pilot developers |
| 🟡 C6 | What accuracy makes this worth using, in developers' own judgement? | ≥70% correct-or-partial | Pilot developers |
| ⚪ C7 | Should the system ever attempt an automated fix, or only advise? | **Advise only.** Automated remediation is a different risk class and a different product. | PO |
| ⚪ C8 | Is analysis latency a requirement? Minutes acceptable? | Minutes acceptable | Pilot developers |
| ⚪ C9 | Do developers want per-failure notification, or a digest? | Per-failure with suppression; digest in Phase 3 | Pilot developers |
| ⚪ C10 | Does anyone outside the dev team need this — support, ops, client? | No, Phase 1–3 | PO |
| ⚪ C11 | Is there an existing ticketing system failures already flow into? | No integration assumed | RPA ops |

---

## D. Data access

| # | Question | Assumed | Ask |
|---|---|---|---|
**Everything below is now an internal conversation with the iBot team, not a vendor.** That is the
biggest practical change from the platform decision: most of these are answerable, and several are
*changeable*.

| 🔴 D1 | What is iBot's log format, path convention, and rotation policy? | Text files in a per-run directory | iBot team |
| 🔴 D5 | **How are a log and its screenshot correlated on disk** — shared run ID, filename convention, or timestamp proximity? | Shared run ID — **timestamp proximity would be fragile and would argue hard for Option A** | iBot team |
| 🟡 D2 | Screenshot format and resolution as written today? | PNG, full desktop resolution | iBot team |
| 🟡 D3 | **Will iBot capture only the failing window instead of the full desktop?** | Not today — **an ask, not a constraint; best security win available (`SECURITY.md` §3.1 C′)** | iBot team |
| 🟡 D3a | **Will iBot emit structured error metadata (exception, stack, activity, code location) as a JSON sidecar?** | Not today — **removes the fingerprint's biggest fragility (`DATA_MODEL.md` §2.0)** | iBot team |
| 🟡 D3b | Will iBot POST the failure event itself (Option A)? On what timeline? | Not today; Option B bridges | iBot team |
| 🟡 D4 | Does the log carry a stack trace and code location, or must we infer it? | Yes, includes activity and location | iBot team |
| 🟡 D6 | How long do logs and screenshots survive on the VM before rotation deletes them? | ≥24h — **sets how long the emitter's spool has to recover from an outage** | iBot team / RPA ops |
| 🟡 D6a | Does iBot ever capture windows outside the bot's own session? | No | iBot team |
| ⚪ D7 | Are there bots whose screens are categorically too sensitive to capture at all? | Assumed none — **likely false; some client screens may need a blocklist** | PO + Security |
| ⚪ D8 | Volume — what is the *actual* current failure rate per day? | 100–2,000 range assumed | RPA ops |
| ⚪ D9 | Do failures cluster per bot within minutes? (Decides whether prompt caching pays — `COST_MODEL.md` §4.2) | Unknown; projections assume no benefit | Measure in Phase 1 |
| ⚪ D10 | Does historical failure data exist to test the fingerprint against before go-live? | Assumed yes — **would materially de-risk the fingerprint** | RPA ops |

---

## E. Assumptions with no owner to ask

Things I decided because there was no one to ask. Each is a place the design could be wrong.

1. **Sonnet 5 for deep analysis, Haiku 4.5 for triage.** Cost/quality judgement, unvalidated
   against real accuracy data. Revisit after Phase 1.
2. **70% dedup hit rate.** Inferred from how RPA failures typically distribute, not measured on
   your data. If it is actually 30%, cost triples — still under $1,500/month, so the design
   survives, but the headline claim does not.
3. **Fingerprint's 4-digit integer threshold** (`DATA_MODEL.md` §2.3). A guess. Needs tuning on
   real logs; too loose merges distinct failures, too strict collapses the hit rate.
4. **30-day analysis reuse TTL.** Arbitrary. Balances freshness against hit rate.
5. **Code re-fetched at analysis time rather than snapshotted at ingest.** Simpler; assumes the
   repo is reachable and the commit still exists.
6. **Vision escalation defaults to text-only when uncertain.** Conservative; cheap because the
   vision premium is only 6% (`COST_MODEL.md` §7).
7. **Platform admins cannot view screenshots.** A deliberate stance that will be argued about.
8. **Standard SQS, not FIFO.** Analysis writes are idempotent on `(fingerprint, commit_sha)`.
9. **Single Postgres instance, no read replica.** Volumes are small; add one if the dashboard
   proves heavy.
10. **No multi-tenancy beyond team-level authorization.** Assumes one client engagement. If this
    serves multiple clients, the data model needs a tenant boundary and **that is a rewrite, not
    an addition** — ask before Phase 1 if there is any chance of it.

13. **The emitter can run on a bot VM without disturbing the bot.** Assumes spare CPU, memory and
    disk, and that security accepts new estate-wide software. Unverified on both counts (B4, B5b).
14. **A 500 MB spool is enough to ride out an outage.** A guess. Depends on failure volume per VM
    and outage length; tune once real rates are known.
15. **Log and screenshot can be correlated on disk without iBot's help.** If correlation is only by
    timestamp proximity, the sidecar will mismatch them under load and Option A becomes mandatory
    rather than preferred (D5).
16. **iBot's log format is stable across versions.** If it drifts between releases, the fingerprint's
    normalization breaks silently — exactly the failure `DATA_MODEL.md` §2.5 versioning is for.
11. **English-language logs and screenshots.** OCR and PII detection are language-sensitive. If
    client applications are non-English, redaction quality drops sharply.
12. **Screenshots are PNG at desktop resolution.** Drives the downscale and token math.

---

## F. The five to answer this week

If bandwidth allows only a handful:

1. **B3** — can a bot VM reach an AWS endpoint over HTTPS? *New top of the list. iBot writes only
   to local disk, so this is the entire ingestion path. If it is no, nothing else in the plan
   matters. Prove it with one VM and one curl — an afternoon, not a workstream.*
2. **A4** — do Bedrock's terms satisfy the client contract? *Blocks everything downstream of
   ingestion. Must be read, not recalled.*
3. **A3** — are unscrubbed names in logs acceptable? *Blocks Phase 1; unlike the screenshot
   questions, Mode 0 does not route around it.*
4. **C3** — what is the MTTR baseline, and has anyone measured it? *Cannot be captured
   retroactively. Miss this window and the pilot cannot demonstrate value no matter how well it
   works.*
5. **B4 / B5** — may we deploy the emitter, and is there already an agent we could extend instead?
   *Decides whether Phase 1's largest workstream exists at all.*

**And start the iBot conversation this week even though it is not on this list** (D3, D3a, D3b).
Those are asks to a colleague rather than blockers, but they need lead time, and two of them —
capture narrowing and structured error metadata — are the best available improvements to the
security posture and to dedup reliability respectively. They were not even askable when the plan
assumed a vendor tool.

**C3 remains the one most likely to be skipped and most expensive to skip.** It is the only question
here with a deadline set by the physics of measurement: once the system is live, the before-state is
gone forever.

