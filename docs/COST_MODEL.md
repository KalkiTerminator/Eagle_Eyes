# Eagle Eyes — Cost Model

**Read §7 first if you read nothing else.** The arithmetic contradicts one of the premises in the
build brief, and it changes what we should optimize.

---

## 1. Pricing basis and a caveat

Planning uses Anthropic first-party list rates as a proxy:

| Model | Input $/MTok | Output $/MTok | Role |
|---|---:|---:|---|
| Claude Haiku 4.5 (`claude-haiku-4-5`) | $1.00 | $5.00 | Triage |
| Claude Sonnet 5 (`claude-sonnet-5`) | $2.00 | $10.00 | Deep analysis |
| Claude Opus 5 (`claude-opus-5`) | $5.00 | $25.00 | Not used; listed for comparison |

**Amazon Bedrock is partner-operated and priced separately.** These numbers are a planning proxy,
not a quote. Before any figure here goes in front of finance, re-derive it from
<https://aws.amazon.com/bedrock/pricing/> for your region. On Bedrock the model IDs carry an
`anthropic.` prefix (`anthropic.claude-sonnet-5`).

Sonnet 5 for deep analysis rather than Opus 5: this is a bounded diagnostic task over supplied
evidence, not open-ended reasoning. Opus would cost 2.5× input and 2.5× output for a job Sonnet
does well. **Revisit this if Phase 1 feedback shows accuracy below the trust threshold** — a wrong
diagnosis costs a developer an hour, which dwarfs any model price difference. Cost is the right
tiebreak only once quality is adequate.

---

## 2. Image token math

Claude tokenizes images by pixel area, roughly **one token per 28×28 patch**:

```
image_tokens ≈ (width_px × height_px) / 784
```

| Resolution | Tokens | Cost on Sonnet 5 |
|---|---:|---:|
| 1024 × 576 | ~753 | $0.0015 |
| **1280 × 720 (chosen default)** | **~1,176** | **$0.0024** |
| 1920 × 1080 | ~2,645 | $0.0053 |
| 2576 × 1449 (Sonnet 5 max) | ~4,761 | $0.0095 |

Sonnet 5 supports high-resolution vision up to **2576 px on the long edge**. We will not use it.
A 1280×720 downscale is legible for error dialogs and UI state, and costs a fifth of full
resolution.

**Verify the formula empirically in Phase 1.** `count_tokens` on representative screenshots, and
log `image_tokens` on every vision call so the assumption is checked against reality rather than
carried forward on faith. The constant has changed across model generations before.

---

## 3. Cost per analysis path

| Path | Model | In | Out | Cost |
|---|---|---:|---:|---:|
| **Dedup hit** | none | 0 | 0 | **$0.000000** |
| **Known pattern** | none | 0 | 0 | **$0.000000** |
| **Triage** | Haiku 4.5 | 3,500 | 150 | **$0.004250** |
| **Deep, text-only** | Sonnet 5 | 14,200 | 1,000 | **$0.038400** |
| **Deep, with vision** | Sonnet 5 | 15,376 | 1,000 | **$0.040752** |

Input composition for deep analysis:

| Component | Tokens | Cacheable? |
|---|---:|---|
| System prompt + output schema | 1,200 | Yes — stable |
| Bot source (relevant file + imports) | 8,000 | **Yes, per bot** — see §4 |
| Sanitized log excerpt | 5,000 | No — per failure |
| Screenshot (vision path) | 1,176 | No |

A full triage-plus-deep-vision journey for one novel failure: **$0.045**.

---

## 4. Prompt caching — less valuable here than expected, and fixable

Two findings that contradict the usual assumption.

### 4.1 The Haiku triage prompt cannot be cached at all

Minimum cacheable prefix is model-dependent. **Claude Haiku 4.5 requires 4,096 tokens.** Our triage
prompt's stable portion is ~600 tokens. It is far below the floor, so it will not cache — and it
fails *silently*: no error, just `cache_creation_input_tokens: 0` forever.

Do not build a caching strategy for triage. Do not report a triage cache hit rate; there will never
be one. (Sonnet 5's minimum is 1,024 tokens, so the deep-analysis prefix does qualify.)

### 4.2 Caching the system prompt saves ~5%; caching the code saves ~37%

The naive placement — cache the system prompt — protects 1,200 of 14,200 input tokens. At a 0.1×
read rate that saves $0.0022 per call, about 5.6%. Barely worth the breakpoint.

The reason is structural: our prompt is almost entirely *variable*. Caching pays when a large fixed
prefix is reused, and ours is small.

**But the bot's source code is stable per bot.** The same bot fails repeatedly, with different
fingerprints, against the same 8,000 tokens of code. Order the prompt so that code sits inside the
cacheable prefix:

```
[ system prompt + schema ]   1,200 tok  ─┐
[ bot source code        ]   8,000 tok  ─┴─ cache_control breakpoint here
[ sanitized log          ]   5,000 tok
[ screenshot             ]   1,176 tok
```

A warm hit then saves 9,200 tokens at 0.9× = **$0.0166 per call, ~37%**.

Requirements and the honest caveat: cache key is per `(bot, commit_sha)`; a code change invalidates
it correctly. Use the 5-minute TTL by default — writes cost 1.25× and reads refresh the timer, so
continuous traffic keeps it warm for free. The 1-hour TTL costs a 2× write and only pays back above
three reads in the window; for a bot failing a handful of times an hour that is a real gamble.

**The caveat: hit rate depends entirely on failure clustering per bot within the TTL.** If failures
are spread evenly across 150 developers' bots, most calls are cold and this saves almost nothing.
If they cluster — which is the normal shape during an incident — it saves a third. We do not know
which regime we are in until Phase 1 measures it. The projections in §7 assume **0%** cache benefit
so the numbers are not resting on an unverified assumption; treat any caching saving as upside.

---

## 5. Deduplication

### 5.1 Design

Full scheme in `DATA_MODEL.md` §2. Cost-relevant properties:

- Fingerprint is computed from **sanitized text only**. No model call, no network egress, no cost.
- It excludes `bot_id`, so the same failure across different bots collapses to one analysis.
- It excludes timestamps, run IDs, and line numbers — the fields that would otherwise make every
  occurrence unique.
- Reuse requires matching code version and no `wrong` feedback (`DATA_MODEL.md` §2.6), so the
  saving never comes at the price of a stale or discredited answer.

### 5.2 Expected hit rate

| Regime | Expected hit rate | Reasoning |
|---|---:|---|
| Steady state | **65–80%** | RPA failures are dominated by recurring causes: selector drift after a UI update, credential expiry, locked files, application timeouts. The long tail of genuinely novel failures is thin. |
| Infrastructure incident | **>99%** | Hundreds of failures within minutes sharing one root cause and one fingerprint. |
| First week of pilot | **~0–20%** | Cache is cold. Every failure is novel. Expect the first week's cost to look alarming and then fall sharply — say so in advance so nobody panics. |

Planning uses **70%**.

### 5.3 Impact

Without dedup at 2,000 failures/day: 2,000 triage + ~1,200 deep = $8.50 + $46.83 = **$55/day**.
With dedup at 70%: **$16.50/day**. A **70% reduction** — dedup is by a wide margin the single most
effective cost control in the system, and the only one that saves 100% on every hit.

### 5.4 The spike case

An infrastructure incident produces 500 failures in two minutes, nearly all sharing a fingerprint.

Failure #1 pays full price (~$0.045). Failures #2–500 hit the fingerprint index and cost **$0**. No
queue message, no worker, no model call. Total incident model cost: **$0.045**.

Cost during a spike is flat, not linear. `ARCHITECTURE.md` §6 and the Phase 1 load test must prove
this rather than assume it.

---

## 6. Tiered routing and the vision escalation gate

Triage decides whether a screenshot is needed. The rule:

**Escalate to vision when the failure is about what was on screen:**
- Selector / UI element not found
- Click, type, or hover failed on a present element
- Unexpected window, modal, or dialog
- Image or OCR match failure
- Application unresponsive or hung
- Timeout waiting for a UI element
- Any failure inside a Citrix / virtual-desktop interaction (the RPA tool sees only pixels there)

**Do not escalate when the failure is about data, I/O, or logic:**
- File not found, permission denied, path errors
- HTTP / API / web-service errors
- Database and SQL errors
- Parse, format, and type-conversion errors
- Null reference in data processing
- Authentication and credential expiry
- Queue and transaction errors
- Arithmetic errors

Default when triage is uncertain: **text-only**. Escalation must be affirmative. §7 explains why
this default costs almost nothing.

---

## 7. What the arithmetic actually says

> The brief states: *"COST EFFICIENCY — vision inputs are expensive."*
>
> **At our resolution, they are not.** A downscaled screenshot adds ~1,176 tokens — **$0.0024**,
> or **6%** of a deep analysis. The vision path costs $0.0408 against the text path's $0.0384.

Ranked by actual saving:

| Lever | Saving | Notes |
|---|---:|---|
| **Deduplication** | **~70%** | 100% on every hit. Dominates everything else. |
| **Known-pattern templates** | ~25% of remaining | No model call at all. |
| **Triage gating out noise** | ~15% of remaining | Cheap model prevents an expensive one. |
| Per-bot code caching | up to 37% of deep calls | Unverified — see §4.2 |
| **Vision escalation gate** | **~6% of deep calls** | Not a major lever. |

This does not make the escalation gate pointless — it is worth keeping for three reasons, none of
them primarily cost:

1. **Privacy.** Every avoided vision call is a screenshot that never reaches a model. Under
   `SECURITY.md`'s framing, that is the strongest argument for the gate.
2. **Latency.** Image processing and transfer add seconds per call.
3. **Quality.** An irrelevant screenshot is a distraction that can degrade a diagnosis.

**Build the gate. Justify it as a privacy and quality control. Do not present it to leadership as
the cost story — dedup is the cost story, and the numbers back that up.**

---

## 8. Projected monthly cost

Funnel per 100 failures ingested: 70 dedup hits ($0) → 30 triaged → 4.5 noise, 7.5 known pattern
($0), 18 deep → 12.6 text, 5.4 vision. Assumes no cache benefit (§4.2).

| Failures/day | Triage | Deep text | Deep vision | **Model/month** |
|---:|---:|---:|---:|---:|
| 100 | $3.83 | $14.51 | $6.60 | **$25** |
| 500 | $19.13 | $72.58 | $33.01 | **$125** |
| 2,000 | $76.50 | $290.30 | $132.04 | **$499** |

### AWS infrastructure, per month

| Component | Cost |
|---|---:|
| ECS Fargate — API (2 tasks) | ~$30 |
| ECS Fargate — workers (avg 2) | ~$30 |
| ECS Fargate — notifier + policy worker | ~$25 |
| RDS PostgreSQL, Multi-AZ (db.t4g.medium) | ~$130 |
| Application Load Balancer | ~$20 |
| S3 (≤150 GB) + requests | ~$5 |
| CloudFront + S3 static UI | ~$5 |
| SQS, KMS, Secrets Manager | ~$8 |
| CloudWatch logs, metrics, alarms | ~$30 |
| **Total** | **~$283** |

### Combined

| Failures/day | Model | Infra | **Total** | Per developer (150) |
|---:|---:|---:|---:|---:|
| 100 | $25 | $283 | **$308** | $2.05 |
| 500 | $125 | $283 | **$408** | $2.72 |
| 2,000 | $499 | $283 | **$782** | $5.21 |

**At 100 failures/day, infrastructure costs 11× the models. Even at 2,000/day it is nearly half.**

The honest conclusion: **model spend is not this system's cost problem.** At the top of the
projected range the entire bill is under $800/month against 150 developers — roughly the loaded
cost of one developer-day. The dominant cost of this project is engineering time, and the second is
AWS baseline.

Two consequences worth acting on:

- The budget guard is **runaway protection**, not a cost-management necessity. Its job is to catch
  a fingerprint regression or a retry loop, not to ration normal operation.
- **Do not trade accuracy for model cost.** At these absolute numbers, a cheaper model that is
  wrong more often is a bad trade by orders of magnitude. One developer-hour lost to a wrong
  diagnosis costs more than a month of vision calls.

---

## 9. Cost controls

### Budget guard

Checked **before** every model call, never after.

| Scope | Limit | Action on breach |
|---|---|---|
| Global daily | $50 (≈3× the 2,000/day projection) | Stop new analyses; dedup + templates continue |
| Global monthly | $1,000 | Stop; page the owner |
| Per team daily | $10 | Throttle that team; others unaffected |
| Per bot hourly | $2 | Throttle that bot — catches a single looping bot |
| Single analysis | $0.50 | Reject; log as anomaly |

The per-bot hourly limit exists because the realistic runaway is one misbehaving bot, not
estate-wide growth.

### Alerting

| Signal | Threshold | Why it matters |
|---|---|---|
| **Dedup hit rate drop** | <50% over 1h | **The highest-value alert.** Fingerprint regression → 3× cost. Leading indicator of a bug, not just a bill. |
| Daily spend | >60% of cap by noon | Early warning |
| Vision escalation rate | >50% of deep | Gate mis-tuned |
| Cost per analysis | >2× baseline | Prompt bloat or a model change |
| Triage cache hit rate | — | **Do not alert. It is always zero (§4.1).** |

### If we had to halve cost

In order, cheapest concession first:

1. **RDS single-AZ** (−$65/mo). At 100/day this alone is a quarter of the bill. Costs failover.
2. **Raise `ANALYSIS_REUSE_TTL` from 30 to 90 days.** Lifts hit rate by an estimated 5–10 points
   for one config change. Costs freshness on slowly-drifting failures.
3. **Disable the vision path entirely.** Saves ~6% of deep-analysis cost — a rounding error. Listed
   here only to make the point: cutting vision to save money is not worth the capability loss.
4. **Reduce CloudWatch retention** (−$15/mo).
5. **Route deep analysis to Haiku 4.5** (−~60% of model spend). **Last resort, and probably never.**
   At these absolute figures the accuracy risk is not worth ~$300/month.

Note what this ordering says: **the first two items halve the bill at low volume without touching
model quality at all.** If someone asks us to cut cost, the answer is infrastructure and TTL
tuning, not capability.
