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
| 🔴 B3 | **Can Exodus reach Bedrock over outbound HTTPS?** Direct, proxy, or allowlist? | Assumed yes — **unverified, and if no the analyzer cannot call a model at all. One command settles it.** | Network / IT |
| 🔴 B4 | **May we install an application on Exodus?** What review does that need? | Yes — but a jump server is a control point into production and may be scrutinised harder than an ordinary host | Security + IT |
| 🔴 B5 | **Can IT create a read-only service account** with access to the VM shares and the code folder? | Yes — **must be share-scoped, never `C$`/`ADMIN$`, never write** | IT / Identity |
| 🟡 B5a | Does the analyzer run under that service account on a schedule, or only in an interactive session? | Interactive — the catch-up scan covers both, so this changes the trigger, not the design | IT |
| 🟡 B5b | Does Exodus have disk encryption? The SQLite database depends on it. | Yes | IT |
| 🟡 B5c | Does the SMTP relay accept mail from Exodus without a new rule? | Yes | IT |
| 🟡 B5d | Which shared folder hosts the HTML reports, and who can read it? | A team share — **the one new place client-derived content lands; needs its own ACL review** | IT + Security |
| 🟡 B3a | Is the shared code folder backed up or version-controlled in any way? | No — manual `.txt` copies only | RPA ops |
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
| ⚪ C1 | ~~Which RPA platform?~~ **Settled: iBot only**, C#/.NET + Selenium + some JavaScript. Web automation, not desktop. | — | — |
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

The share layout is known:
`Network_Sharing_Folder/data/{service line}/{bot number}/{year}/{month}/{date}/logs/user logs/{logs,screenshot}`
— which gives service line, bot number and date structurally, with no content parsing. What remains
is what happens *inside* a date folder.

| ✅ D5 | ~~How are a log and its screenshot paired?~~ **Answered: timestamp only** — filenames are `2026-09-11_09-41-09.png`, no run ID. Pairing rule and refusal-on-ambiguity in `ARCHITECTURE.md` §4.4. | — | — |
| 🟡 D5a | **Does the log line record the screenshot filename?** If so, pairing is exact and the refusal rule stops mattering. | No — timestamp only | iBot team |
| 🟡 D5b | **Does a failing run stop at the first error, or catch per item and continue?** Continuing produces bursts of screenshots and makes timestamp pairing much harder. | Stops at first error | iBot team |
| 🔴 D7 | **How does `bot_number` map to a file in the code folder?** Exact name, prefix, per-service-line subfolder? | `{bot_number}.txt` — needs confirming | PO / RPA ops |
| 🟡 D10 | **Is browser version pinned, or does Chrome auto-update on the bot VMs?** Auto-update is handled by normalization now, but a pinned fleet also removes a class of `SessionNotCreatedException` failures. | Auto-updates | RPA ops / IT |
| 🟡 D1 | What is iBot's log format and rotation policy? | Text, one file per run | iBot team |
| 🟡 D2 | Screenshot format and resolution as written today? | PNG, full desktop resolution | iBot team |
| 🟡 D3 | **Will iBot capture only the failing window instead of the full desktop?** | Not today — an ask, not a constraint. Under Mode 0 this is now an efficiency and Modes 1–2 question, no longer a blocker. | iBot team |
| 🟡 D3a | **Will iBot emit structured error metadata as a JSON sidecar?** | Not today — **removes the fingerprint's biggest fragility (`DATA_MODEL.md` §2.0)** | iBot team |
| 🟡 D4 | Does the log carry a stack trace and code location, or must we infer it? | Yes, includes activity and location | iBot team |
| 🟡 D6 | How long do logs and screenshots survive on the share before rotation deletes them? | ≥30 days — **sets how far back a catch-up scan can recover, and whether a report's screenshot link still resolves** | RPA ops |
| 🟡 D8 | **Who keeps the code folder current, and how stale does it get?** | Kept current — **`ARCHITECTURE.md` §4.5 flags staleness rather than trusting this** | PO / RPA ops |
| ⚪ D9 | Is the tree structure stable, or does it vary by service line? | Stable — the path template is configurable in case it is not | RPA ops |
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
5. **Code read from the shared folder at analysis time.** The only option — there is no repo and no
   per-run snapshot. Carries the staleness risk in item 14.
6. **Vision escalation defaults to text-only when uncertain.** Conservative; cheap because the
   vision premium is only 6% (`COST_MODEL.md` §7).
7. **Platform admins cannot view screenshots.** A deliberate stance that will be argued about.
8. **Re-scans are idempotent on `log_path`.** A re-run over the same folder writes nothing new.
9. **SQLite is sufficient for Phase 1.** One host, one writer. Phase 3 ports to Postgres
   (`DATA_MODEL.md` §8).
10. **No multi-tenancy beyond team-level authorization.** Assumes one client engagement. If this
    serves multiple clients, the data model needs a tenant boundary and **that is a rewrite, not
    an addition** — ask before Phase 1 if there is any chance of it.
11. **English-language logs and screenshots.** OCR and PII detection are language-sensitive.
12. **Screenshots are PNG at desktop resolution.** Drives the downscale and token math.
13. **Exodus can reach Bedrock.** The whole design rests on it and it is unverified (B3).
14. **The code folder's `.txt` files are current enough to reason about.** Manually maintained, with
    no version control and no record of which version a bot was running. Mitigated by an mtime
    staleness flag, not solved (`ARCHITECTURE.md` §4.5).
15. **Log and screenshot can be paired inside a date folder.** If it is timestamp proximity only,
    concurrent failures mismatch and we attach nothing rather than guess (D5).
16. **iBot's log format is stable across versions.** If it drifts, the fingerprint's normalization
    breaks silently — exactly what `DATA_MODEL.md` §2.5 versioning exists for.
17. **SMB reads from Exodus are fast enough** to walk a day's folders for all pilot bots in a
    reasonable run. Unmeasured; latency over SMB to many VMs could dominate runtime.
18. **A file that stops changing is complete.** The scanner may otherwise read a log mid-write.
    Mitigated by requiring a stable mtime for N seconds before processing.
19. **Overnight and weekend gaps are acceptable in Phase 1.** The analyzer only runs when Exodus is
    open. Fine for a pilot; a real limitation at 150 developers (Phase 3 addresses it).

---

## F. The five to answer this week

If bandwidth allows only a handful:

Two of these are an afternoon each, and both are blocking. Do them first.

1. **B3** — can Exodus reach Bedrock over HTTPS? *One command from the jump server. If the answer is
   no, the analyzer cannot call a model and nothing else in the plan matters.*
2. **D5** — how are a log and its screenshot paired inside a date folder? *One directory listing
   settles it. If it is timestamp proximity only, screenshots become unreliable for concurrent
   failures and the correlator has to refuse rather than guess — a design consequence, not a detail.*
3. **A4** — do Bedrock's terms satisfy the client contract? *Must be read, not recalled.*
4. **A3** — are unscrubbed names in logs acceptable? *Blocks Phase 1. Mode 0 routes around the
   screenshot questions but not this one.*
5. **C3** — what is the MTTR baseline, and has anyone measured it? *Cannot be captured
   retroactively.*

**Start the iBot conversation this week even though it is no longer blocking** (D3, D3a). Structured
error metadata would remove the fingerprint's largest fragility, and capture narrowing is still the
best upstream improvement available — but neither gates Phase 1 now, because Mode 0 copies nothing
and sends nothing.

**What dropped off this list is worth noting.** Two drafts ago the top questions were about
screenshot permission and estate-wide agent deployment. Reading existing shares from one host
removed both: there is no agent, and in Mode 0 there is no copy to get permission for.

**C3 remains the one most likely to be skipped and most expensive to skip.** It is the only question
here with a deadline set by the physics of measurement: once the system is live, the before-state is
gone forever.

