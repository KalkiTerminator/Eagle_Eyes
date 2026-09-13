# Reference samples

Hand-written artifacts shaped like what iBot produces. **Every byte is invented** — no real system,
no real people, no real policy numbers. They exist so the parser and the fingerprint can be built
against something with realistic shape.

Nothing here should ever be replaced with something real (`SECURITY.md` §11).

---

## What we now know about the real thing

Two facts, confirmed, that reshaped the design:

1. **Bots are C#/.NET driving Selenium**, with some JavaScript executed through
   `IJavaScriptExecutor`. This is **web automation**, not Windows-desktop automation — an entirely
   different failure taxonomy from the one the first draft assumed.
2. **Screenshot filenames carry a date and time only** — `2026-09-11_09-41-09.png`. No run ID, so
   pairing a screenshot to a log depends on the clock (`ARCHITECTURE.md` §4.4).

Earlier samples modelled a low-code Windows-desktop tool. They were wrong and have been deleted.

---

## Files

| File | What it is |
|---|---|
| `code_1_RemittancePosting.cs.txt` | C# Selenium process: ChromeDriver, `WebDriverWait`, `ExpectedConditions`, a JS-executor workaround for an Angular field |
| `code_2_ClaimIntake.cs.txt` | C# Selenium **plus** a Windows file dialog Selenium cannot see — the mixed web/desktop case |
| `log_1_click_intercepted.log` | `ElementClickInterceptedException` — a session-warning banner covers the tab. **Vision case.** |
| `log_2_stale_element.log` | `StaleElementReferenceException` during `SendKeys`. **Not** a vision case, see below. |
| `log_3_wait_timeout.log` | `WebDriverTimeoutException ---> NoSuchElementException` — a wrapped chain |
| `screenshot_folder_listing/` | What a real screenshot folder listing looks like, including two files 13 seconds apart |

The logs deliberately carry what real logs carry and tidy examples do not: CRLF endings, .NET inner
exception chains, retries logged as WARN before the final ERROR, a rotation elision marker, and
Selenium's `(Session info: chrome=…)` trailer.

---

## What these changed in the design

### The Chrome-update problem — the most serious finding so far

Selenium appends the browser build to **every** exception message:

```
stale element reference: element is not attached to the page document
  (Session info: chrome=128.0.6613.120)
```

Chrome auto-updates roughly every four weeks. Without a rule to drop that trailer, **the morning
after an estate-wide rollout every fingerprint changes at once** — the dedup cache goes cold for
every bot simultaneously, and it recurs every month forever.

A cold cache is **3.3×** the warm cost: at 2,000 failures/day, $16.63/day becomes $55.43/day until
it re-warms. And it is silent — analyses stay correct, only the bill moves.

Fixed by dropping the trailer and normalizing version strings *before* the integer rule (otherwise
`128.0.6613.120` half-mangles into `128.0.<NUM>.120`, which still differs between builds).

### Pixel coordinates fragment too

`is not clickable at point (642, 318)` varies with window size, so the same overlay bug on two
differently-sized screens fingerprinted differently. Normalized to `at point (<X>,<Y>)`. The
diagnostic part — *which* element intercepted the click — is kept.

### Earlier findings, from the first round of samples

- **Fingerprinting the outer exception type.** `WebDriverTimeoutException ---> NoSuchElementException`
  would have keyed on the wrapper. Fixed by unwrapping the chain (`DATA_MODEL.md` §2.2a).
- **The `0x…` rule destroyed HRESULTs**, merging distinct COM faults.
- **CRLF rode into the hash**, so one failure fingerprinted differently across platforms.

### One judgement call worth revisiting

`StaleElementReferenceException` is classified **text-only**, not a vision case, even though it is a
UI exception. By the time the screenshot is taken the page has re-rendered, so the image shows a
state that looks perfectly healthy and can actively mislead the diagnosis. If pilot feedback shows
developers wanting the screenshot here anyway, that is cheap to change — `COST_MODEL.md` §6.

---

## Still unknown

1. **Does the real log record the screenshot filename?** These samples log `Screenshot captured`
   with a timestamp only, matching the date-time filenames. If the real log names the file, pairing
   becomes exact and the refusal rule in `ARCHITECTURE.md` §4.4 stops mattering.
2. **Real timestamp format, log level names, and encoding** (UTF-8 vs UTF-16 vs a code page).
3. **Whether a failing run stops at the first error** or catches per item and continues. The sample
   processes rethrow, so one run produces one screenshot — if real ones continue, screenshots arrive
   in bursts and timestamp pairing gets much harder.

One real log file, sanitized by hand and reviewed before it leaves the estate, answers all three
(`OPEN_QUESTIONS.md` D1; the permitted exception in `SECURITY.md` §11).
