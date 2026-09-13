# Eagle Eyes

Analyses RPA bot failures. Reads the execution log, the error screenshot and the bot's source
code, correlates them, and produces a root cause and a suggested fix.

**Status: testable, not deployable.** The pipeline runs end to end against synthetic data with no
credentials. It has not been run against a real estate, the diagnoses have not been judged by
anyone, and several things listed under [What is not built](#what-is-not-built) are missing.

---

## Try it in two minutes

No credentials, no AWS account, no cost. Python 3.10+ and nothing else.

```bash
python3 -m eagle_eyes --doctor              # is this machine ready?

python3 tools/make_fixtures.py --root ./sandbox     # 251 synthetic failures

python3 -m eagle_eyes \
    --target ./sandbox/Network_Sharing_Folder/data/FINANCE_AP/BOT201 \
    --share-root ./sandbox/Network_Sharing_Folder \
    --code-root  ./sandbox/code_folder
```

You get a review table you can change before anything is sent, then analysis, then HTML reports.
`--backend mock` is the default, so no model is called and the diagnosis says so plainly.

```bash
python3 -m eagle_eyes ... --dry-run    # show what would be analysed, then stop
python3 -m eagle_eyes ... --stats      # what the database holds
```

Run the tests — 312 checks, none needing a credential:

```bash
for t in tests/*.py; do python3 "$t" ./sandbox; done
```

## Using a real model

```bash
pip install 'anthropic[bedrock]'

python3 tools/check_model.py --backend byok        # needs ANTHROPIC_API_KEY
python3 tools/check_model.py --backend bedrock --region us-east-1

python3 -m eagle_eyes ... --backend byok --budget 1.00
```

**Set a budget before the first real run.** A correct pass over the sandbox costs about $0.60;
the same pass with dedup broken costs about $11 for identical information. `--budget` turns that
into a cheap early warning.

Use a **development** account or a personal key here, never client production credentials — the
data is synthetic, but credential provenance is a separate question from data provenance.

## How it works

```
discover  ->  sanitize  ->  fingerprint  ->  dedup  ->  triage  ->  diagnose  ->  report
```

| Stage | What it does |
|---|---|
| **discover** | Walks the share, pairs each log with its screenshot and the bot's code |
| **sanitize** | Removes PII and credentials *before* anything is stored or sent |
| **fingerprint** | Reduces the failure to a stable identity so repeats are recognised |
| **dedup** | A repeat costs nothing — the largest single saving |
| **triage** | Cheap model: noise, known pattern, or novel; and whether the screenshot is needed |
| **diagnose** | Stronger model, correlating log + code + screenshot |
| **report** | HTML per failure, plus email with suppression |

Two properties worth knowing:

**Screenshots are never copied.** In the default mode the image stays where the bot wrote it; the
report links to it, so your existing file permissions still decide who can open it. Nothing is sent
to a model.

**It refuses rather than guesses.** If two failures happened seconds apart and the screenshot
cannot be matched with confidence, none is attached. If the model's answer cannot be parsed, you
get "analysis did not complete" at zero confidence — never an invented cause.

## Where it puts things

| | |
|---|---|
| Windows | `%LOCALAPPDATA%\EagleEyes\` |
| macOS | `~/Library/Application Support/EagleEyes/` |
| Linux | `~/.local/share/eagleeyes/` |
| Portable | `data/` beside the app, if a `portable.txt` marker is present |
| Override | `EAGLE_EYES_DATA_DIR` |

Sources can be a UNC path, a mapped drive, a local folder or a mount — all the same to it.

## Sharing dedup between machines

Each install keeps its own database, so ten installs means ten dedup caches and the same failure
analysed ten times — roughly **3× the cost**. Point them at one shared folder instead:

```bash
python3 -m eagle_eyes ... --shared-cache \\fileserver\eagle-eyes-cache
```

The folder must already exist; a path that does not is reported, never created. (A typo'd share
that silently became a private cache would have every install reporting a healthy cache while each
paid full price.) An unreachable share degrades to "no cache" and breaks nothing.

## What is not built

| | |
|---|---|
| Language support | Log parsing is tuned to C#/.NET + Selenium. Other languages need the profile work. |
| LLM providers | Anthropic only (Bedrock, or your own key). |
| RBAC | Roles exist in the data model and every repository requires a principal, but a local install cannot enforce them against its own operator. Real enforcement needs the server. |
| Known-pattern templates | The zero-cost path exists; nothing populates it. |
| Metrics and structured logging | Only the budget guard. |

## Development

```
eagle_eyes/       runtime, discovery, selection, sanitize, fingerprint,
                  model_gateway, cache, analysis, storage, report, notify
eagle_eyes/prompts/   version-controlled prompt files
tools/            fixture generator, model connectivity check
tests/            312 checks, no credentials required
docs/             architecture, security, data model, cost model, roadmap
```

Nothing outside `model_gateway.py` may import a model SDK; `tests/test_boundaries.py` fails the
build if anything does. The schema in `eagle_eyes/schema.sql` is authoritative and
`docs/DATA_MODEL.md` embeds it verbatim — a test fails if they drift.

**Never put real client logs, screenshots or code on a development machine.** The fixture
generator exists so that is never a judgement call; see `docs/SECURITY.md` §11.
