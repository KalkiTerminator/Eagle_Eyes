# Eagle Eyes — Local Development

The client has AWS Bedrock. Until the real environment is available, **the client environment is
simulated on a personal machine**: local folders stand in for the VM network shares and the code
folder.

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
  backend: mock          # mock | bedrock
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

## 4. Running without AWS credentials

`model.backend: mock` returns canned, schema-valid responses. The full pipeline — scan, correlate,
sanitize, fingerprint, dedup, route, render, notify — runs end to end with no credentials, no
network and no cost.

This is not only a convenience. Per the build kit's requirement, **routing, the escalation gate,
fallback behaviour and cost accounting must all be testable without a network call.** The mock
backend is how that requirement is met, and CI uses it exclusively.

Three backends:

| Backend | Use |
|---|---|
| `mock` | Default. Canned responses keyed by fingerprint. Zero cost. CI runs here. |
| `record` | Real Bedrock call, response saved to `fixtures/responses/`. Run deliberately, costs money. |
| `bedrock` | Live. |

`record` then `mock` gives realistic model output in tests without paying on every run. Scrub
recorded responses before committing — they are derived from whatever went in.

### When you do have credentials

Bedrock model IDs carry the `anthropic.` prefix. Use the Bedrock client class rather than pointing
the first-party client at a different base URL:

```python
from anthropic import AnthropicBedrockMantle
client = AnthropicBedrockMantle(aws_region="...")   # model: "anthropic.claude-sonnet-5"
```

**Set a low budget guard before the first live run.** `COST_MODEL.md` §9 has the production caps; on
a personal machine set them far lower. A loop over 244 fixture failures with dedup accidentally
disabled is ~250 deep analyses — around $10, and entirely avoidable.

---

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

**That last row deserves emphasis.** The fixtures were built to exercise dedup, so a high hit rate is
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
