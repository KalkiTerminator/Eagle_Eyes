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

**Capture at the target size rather than downscaling after the fact.** iBot writes the screenshot,
and iBot is ours — having it capture the failing window at 1280×720 means we never store, ship, or
process the surplus pixels. That saves VM disk and estate bandwidth as well as tokens, and it is the
same change `SECURITY.md` §3.1 Option C′ wants for privacy reasons. One ask, two payoffs.

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
| Steady state | **65–80%** | RPA failures are dominated by recurring causes: selector drift after a UI update, credential expiry, locked files, application timeouts. The long tail of genuinely novel failures is thin. A single platform (iBot) means one log format and one exception vocabulary, which should push this toward the upper end — multi-platform estates fragment the fingerprint namespace. |
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

Cost during a spike is flat, not linear. The Phase 3 load test (`ROADMAP.md`) must prove
this rather than assume it.

---

## 6. Tiered routing and the vision escalation gate

Triage decides whether a screenshot is needed. The rule:

The bots are C#/.NET driving **Selenium**, so the taxonomy is web-automation exceptions, not
Windows-desktop ones.

**Escalate to vision — the screen shows the answer:**

| Exception | Why the screenshot decides it |
|---|---|
| `ElementClickInterceptedException` | Selenium names the intercepting element, but *why* it is there — a cookie banner, a session-warning bar, a modal — is visible only on screen. **The single best vision case in the whole taxonomy.** |
| `NoSuchElementException` | Did the page render? Did it render something else — an error page, a login redirect, an empty result? |
| `WebDriverTimeoutException` | What was the page doing while the wait expired: spinner, blank, partial render, error toast? |
| `ElementNotInteractableException` | Element present but hidden, disabled, or covered |
| `UnhandledAlertException` | The alert text is on screen |
| Desktop dialog failures (`DesktopWindow.WaitFor`) | Outside Selenium's view entirely; pixels are the only evidence |

**Do not escalate — the log already says it:**

| Exception | Why |
|---|---|
| `StaleElementReferenceException` | A timing/re-render fault. The screenshot shows the *post*-failure DOM, which is not the state that went stale. |
| `WebDriverException: net::ERR_*` | Network layer, nothing visual |
| `System.IO.*`, file and path errors | No browser involvement |
| `SqlException`, data access | No browser involvement |
| Credential and auth failures returning a clear code | The log carries the reason |
| `SessionNotCreatedException` (driver/browser version mismatch) | Infrastructure; the message is self-explanatory |

`StaleElementReferenceException` is the one worth arguing about. It is tempting to escalate because
it is a UI exception — but by the time the screenshot is taken the page has already re-rendered, so
the image shows a state that looks fine and can actively mislead the diagnosis. Leave it text-only.

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

### Infrastructure, per month

Almost nothing, because there is almost no infrastructure. The analyzer runs on Exodus, a server
that already exists and is already paid for; storage is a SQLite file on its disk; the only external
call is to Bedrock.

| Component | Cost |
|---|---:|
| Exodus jump server | **$0 — already exists** |
| SQLite storage (a few GB/year on existing disk) | ~$0 |
| Internal SMTP relay | $0 — existing |
| Reports on an existing share | ~$0 |
| Bedrock data transfer | negligible |
| **Total** | **≈ $0** |

The previous design projected ~$283/month for ECS, RDS Multi-AZ, an ALB, S3 and CloudWatch. **All of
it is gone.** Reading shares from one host that already exists removed the entire AWS footprint
except the model calls themselves.

### Combined

| Failures/day | Model | Infra | **Total** | Per developer (150) |
|---:|---:|---:|---:|---:|
| 100 | $25 | ≈$0 | **~$25** | $0.17 |
| 500 | $125 | ≈$0 | **~$125** | $0.83 |
| 2,000 | $499 | ≈$0 | **~$499** | $3.33 |

**The whole system now costs less than $500/month at the top of the projected range**, and model
spend is 100% of it.

That changes one conclusion from the earlier draft and reinforces another:

- **Changed:** infrastructure is no longer the dominant cost — it is zero. Dedup and routing now
  govern the entire bill, so the cost controls in §9 matter more than they did.
- **Reinforced, harder than before:** do not trade accuracy for model cost. The entire annual spend
  at 2,000 failures/day is about $6,000 — comfortably under the loaded cost of a single developer
  for a month. One developer-hour lost to a confidently wrong diagnosis is worth more than a week of
  vision calls.

The real cost of this project is engineering time. It always was; now it is not even close.

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

One risk specific to this design: **a catch-up scan after a long gap.** If Exodus is unopened over a
weekend or a holiday, the next run finds a large backlog and processes it in one burst. Dedup should
absorb most of it, but the daily cap must be a cap on the *run*, not on wall-clock time, or a Monday
morning catch-up will trip it and stall legitimate work. Size the cap against the largest plausible
backlog, not the average day.

### Alerting

| Signal | Threshold | Why it matters |
|---|---|---|
| **Dedup hit rate drop** | <50% over 1h | **The highest-value alert.** A cold cache costs 3.3× a warm one. Two known causes: a fingerprint regression, and a **browser update** — Selenium stamps the Chrome build into every exception message, so an estate-wide Chrome rollout used to reset every fingerprint at once (`DATA_MODEL.md` §2.3). Normalization handles it now; the alert is the backstop if a new version format slips through. |
| Daily spend | >60% of cap by noon | Early warning |
| Vision escalation rate | >50% of deep | Gate mis-tuned |
| Cost per analysis | >2× baseline | Prompt bloat or a model change |
| Triage cache hit rate | — | **Do not alert. It is always zero (§4.1).** |

### If we had to halve cost

In order, cheapest concession first:

1. **Raise `ANALYSIS_REUSE_TTL` from 30 to 90 days.** One config change; lifts hit rate by an
   estimated 5–10 points. Costs freshness on slowly-drifting failures. Free otherwise.
2. **Promote recurring fingerprints to templates aggressively.** A template response costs nothing.
   Every fingerprint with consistent `correct` feedback that becomes a pattern is a permanent saving.
3. **Trim the log excerpt and code sent for deep analysis.** Input is 14,200 tokens, and most of it
   is code. Sending the failing function plus its callers rather than the whole file could cut
   deep-analysis cost by a third — and may well improve the diagnosis by removing noise.
4. **Disable the vision path entirely.** Saves ~6% of deep-analysis cost — a rounding error. Listed
   only to make the point: cutting vision to save money is not worth the capability loss.
5. **Route deep analysis to Haiku 4.5** (−~60% of model spend). **Last resort, and probably never.**
   At these figures the accuracy risk is not worth ~$300/month.

The ordering changed with the infrastructure. Previously the first two items were AWS line items
that halved the bill without touching quality. There are no AWS line items now, so every lever acts
on the model path — and the first three are still free. **If asked to cut cost, tune reuse, templates
and prompt size. Do not cut capability; there is not enough money in it to matter.**
