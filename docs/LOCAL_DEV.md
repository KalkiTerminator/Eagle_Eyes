# Eagle Eyes — Local Development

The client has AWS Bedrock. Until the real environment is available, development runs with **real
Bedrock calls against a wholly synthetic estate**: local folders stand in for the VM network shares
and the code folder, and every log, screenshot and code file is fabricated.

That combination is deliberate, and it is the best of the available options:

- **Real model behaviour.** Diagnosis quality, latency, token counts and cost are measured, not
  guessed. Prompt work against a mock teaches you nothing about whether the answers are any good.
- **Zero data-governance exposure.** Nothing real ever leaves anything. No client PII, no client
  code, no client screens. **This setup needs no security sign-off to run**, which is why it can
  start today while the questions in `SECURITY.md` §9 are still open.

---

## 1. The rule that matters most

> **Never copy real client logs, screenshots or code onto a personal machine.**

Everything in `SECURITY.md` — the sanitizer, the access control, the retention policy, the decision
not to copy screenshots at all — is defeated the moment a real failure folder is dragged onto a
laptop to "test with realistic data". A personal machine has none of those controls and is not in
scope for any of them.

`tools/make_fixtures.py` exists so that this never has to be a judgement call. It generates a
complete synthetic estate with realistic structure and fabricated content. **If the fixtures are not
realistic enough, improve the generator — do not substitute real data.**

The one legitimate exception is a *single* log file, sanitized by hand, shared for the explicit
purpose of getting the parser right (`OPEN_QUESTIONS.md` D1). That is a reviewed one-off, not a
workflow.

---

## 2. Environment profiles

Local, Exodus and client differ only in configuration. One code path, three profiles.

```yaml
# config/local.yaml
environment: local
share_root:    ./sandbox/Network_Sharing_Folder
code_root:     ./sandbox/code_folder
database:      ./sandbox/eagle_eyes.db
reports_out:   ./sandbox/reports
model:
  backend: bedrock       # real calls, synthetic inputs
  region:  us-east-1
  triage:  anthropic.claude-haiku-4-5
  deep:    anthropic.claude-sonnet-5
budget:
  daily_usd:    2.00     # far below production; see section 4
  per_run_usd:  0.50
  single_call_usd: 0.05
notify:
  backend: log           # log | smtp
screenshot_mode: 0
```

```yaml
# config/exodus.yaml
environment: exodus
share_root:    \\<vm-or-dfs>\Network_Sharing_Folder
code_root:     \\<fileserver>\code_folder
database:      D:\EagleEyes\eagle_eyes.db
reports_out:   \\<fileserver>\eagle-eyes-reports
model:
  backend: bedrock
  region:  <client region>
  triage:  anthropic.claude-haiku-4-5
  deep:    anthropic.claude-sonnet-5
notify:
  backend: smtp
screenshot_mode: 0
```

Nothing in the application may branch on `environment`. It is a label for logs and reports. Every
behavioural difference goes through a named setting, so a code path that only ever runs in
production is a code path that was never tested.

**Paths are `pathlib.Path` throughout, never strings concatenated with `/` or `\`.** Local paths are
POSIX, the real ones are UNC. This is the single likeliest source of "worked on my machine".

---

## 3. Generating the estate

```bash
python3 tools/make_fixtures.py --root ./sandbox
```

```
sandbox/
  Network_Sharing_Folder/data/<service line>/<bot>/<year>/<month>/<day>/
      logs/user logs/logs/         *.log
      logs/user logs/screenshot/   *.png   (1280x720, ~8 KB each)
  code_folder/<bot>.txt
```

Deterministic for a given `--seed`, so two developers on the same seed get byte-identical trees and
a failing test reproduces exactly.

### What it deliberately contains

| Scenario | Count | Exercises |
|---|---:|---|
| A — same root cause, many bots, several days | 25 | Dedup across bots; `bot_id` correctly excluded from the hash |
| B — incident spike, one cause | 200 | **Must collapse to one fingerprint and one model call** |
| C — assorted distinct causes | 15 | Each analysed once; triage routing; vision escalation gate |
| D — log with no screenshot | 1 | Degrade to text-only, don't fail |
| E — two failures 2s apart on one bot | 2 | **Ambiguous pairing — must refuse to attach, not guess** |
| F — bot with no code file | 1 | Log-only analysis with capped confidence |

D, E and F are one row each and matter more than the volume suggests: they are the paths where a
plausible implementation quietly does the wrong thing.

`vision: True|False` on each template in the generator is the ground truth for the escalation gate
(`COST_MODEL.md` §6). A test can assert triage's decision against it without any model call.

---

## 4. Bedrock: real calls, synthetic inputs

### Check it works before building on it

```bash
pip install 'anthropic[bedrock]'
python3 tools/check_bedrock.py --region us-east-1
```

One small call per model. On failure it names which link is broken — credentials, expired token,
model access, region, model ID, throttling, or no egress — and what to do about it. Run it again on
Exodus the day access is granted; that is where it is most likely to report no egress.

**The commonest first-run failure is not a network problem.** Bedrock requires model access to be
enabled explicitly, **per account and per region**, in the Bedrock console under *Model access*. Until
you do that you get `AccessDeniedException` even with perfect credentials on a perfectly connected
machine, and it reads like an IAM problem when it is not.

### Which AWS account

**Use a development account, not client production credentials.**

The data is synthetic, so there is no data-governance issue — but credential provenance is a separate
question from data provenance. Client production credentials sitting in `~/.aws/credentials` on a
personal machine is its own exposure, and it is not made acceptable by the fact that you are only
sending fabricated logs through them. Keep dev spend on a dev account where the bill is also legible.

### Cost, and the one way to get this wrong

Per `COST_MODEL.md` §3, a full triage-plus-deep-analysis journey is about **$0.045**. The sandbox
holds 244 failures, but dedup collapses them to 14 unique fingerprints — so a correct full run costs
roughly **$0.60**.

A run with dedup accidentally disabled is ~250 analyses: **about $11**, for identical information.

That gap is the point. **Set the budget guard before the first live run** — the `budget` block above
caps a local run at $2. It is also a genuinely useful test: if a local run trips the cap, dedup is
broken, and you have found it for $2 instead of discovering it in production.

### Backends

| Backend | Use |
|---|---|
| `bedrock` | **Default for local development.** Real calls, synthetic inputs. |
| `record` | Real call, response saved to `fixtures/responses/`. Run deliberately. |
| `mock` | Canned responses. **CI runs here exclusively** — no credentials, no cost, no network. |

`mock` is not a lesser fallback; it is a requirement. Per the build kit, routing, the escalation gate,
fallback behaviour and cost accounting must all be testable without a network call. A test suite that
needs AWS credentials is a test suite that will be skipped.

`record` then `mock` gives tests realistic model output without paying on every run.

### Client code

Use the Bedrock client class rather than pointing the first-party client at a different base URL.
Model IDs carry the `anthropic.` prefix:

```python
from anthropic import AnthropicBedrockMantle
client = AnthropicBedrockMantle(aws_region="us-east-1")
resp = client.messages.create(model="anthropic.claude-sonnet-5", max_tokens=4096, messages=[...])
```

All of this lives behind `model_gateway` (`ARCHITECTURE.md` §5). Nothing else imports the SDK, so the
day this moves to the client's account — or to a VPC endpoint — one module changes.

## 5. What local development cannot tell you

Honest limits. Each of these is a real risk that the sandbox actively hides:

| Hidden here | Why it matters | Where it surfaces |
|---|---|---|
| **SMB latency** | Local reads are instant; reading a day of folders across many VMs may dominate runtime | First run on Exodus |
| **Real log format** | The generator's format is invented. Fingerprint tuning against it is tuning against fiction. | The moment a real sample arrives |
| **Real pairing convention** | Fixtures pair by filename; reality may only offer timestamps | `OPEN_QUESTIONS.md` D5 |
| **Files being written as we read** | No partial writes locally | Under real load |
| **Permissions and locked files** | Everything is readable here | On the real share |
| **Code drift** | Fixture code files are always consistent with the failure | Once real `.txt` files are used |
| **Real dedup hit rate** | The 94.3% measured here is a property of the generator, not of your estate | Phase 1, against real logs |
| **Whether diagnoses are actually right** | Bedrock is real, but it is reasoning about invented failures in an invented log format. Quality here says little about quality on real ones. | Pilot feedback |

**Two rows deserve emphasis.** The dedup rate is guaranteed high by construction, and the diagnosis
quality is measured against fiction. Real Bedrock calls make the *mechanism* real — routing, token
counts, latency, cost, schema validation, fallback behaviour — and none of that is the same as
knowing the answers are good.

**On the dedup rate specifically:** The fixtures were built to exercise dedup, so a high hit rate is
guaranteed by construction. It proves the mechanism works; it says nothing about your estate.
`COST_MODEL.md` §5.2 assumes 65–80% from real-world reasoning, and that assumption stands until
measured on real logs.

---

## 6. What the fixtures already caught

The generator earned its cost before any application code existed.

Running the documented fingerprint over the synthetic estate showed the 200-failure spike
fragmenting into **four** fingerprints instead of one. Cause: the normalization rule was written as
`\b\d{4,}\b`, and there is no word boundary between a digit and a letter — so `15000ms` never
matched, and each distinct timeout value produced a different fingerprint.

In production this would have failed silently, and hardest under exactly the load the cost control
exists to absorb. Fixed to `(?<!\d)\d{4,}(?!\d)`; dedup across the fixtures went from 90.6% to 94.3%
and the spike now collapses to exactly one. Written up in `DATA_MODEL.md` §2.3.

A second, smaller finding: bot numbers were not unique across service lines, so `<bot>.txt` silently
overwrote code files. Whether real bot numbers are globally unique is now `OPEN_QUESTIONS.md` D7 —
if they are not, the code folder must be keyed by `(service_line, bot_number)`.

Build the fixtures before the pipeline, not after.
