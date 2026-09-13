# Reference samples — plausible, not real

Hand-written artifacts that approximate what iBot probably produces. **Every byte is invented.**
They exist so the parser and the fingerprint can be developed against something with realistic
shape, and so the questions below can be answered by comparison rather than description.

Nothing here came from a real system. Nothing here should ever be replaced with something that did
(`SECURITY.md` §11).

---

## Code — three candidate formats. Which is closest?

iBot has only a copy function, so what lands in the `.txt` is whatever the designer puts on the
clipboard. That could be any of these shapes, and they are different enough to matter:

| File | Shape | If this is it |
|---|---|---|
| `code_A_steptable.txt` | Tab-separated step table: step, action, target, value, timeout, on-error | Easiest to parse and the best case. Step numbers give precise code locations, and `OnError` columns are directly useful to a diagnosis. |
| `code_B_script.txt` | VB-like in-house DSL with `Sub Main`, `On Error Goto` | Reads like source. Good for the model, and line numbers in a stack trace may map to it directly. |
| `code_C_workflow.txt` | XAML-ish workflow XML with `DisplayName` attributes | Most verbose — 3–4× the tokens for the same logic, which shows up in `COST_MODEL.md` §3. Worth stripping attributes before sending. `DisplayName` maps cleanly to the activity names in logs. |

**Tell me which is closest and I will drop the other two.** If it is none of them, a screenshot of
the designer with a few steps visible is enough — I do not need the content, only the shape.

The format choice has real consequences: C costs noticeably more per analysis than A, and A gives a
far better code-location key for the fingerprint.

---

## Logs — one format, three failures

All three use the same invented iBot log format, deliberately including the things that break
parsers written against tidy examples:

- **CRLF line endings** and trailing whitespace
- **.NET inner-exception chains** (`---> …` / `--- End of inner exception stack trace ---`)
- **Retry attempts logged as WARN** before the final ERROR
- **A line from another thread** interleaved mid-sequence (`[T:03] HeartbeatService`)
- **An elision marker** where rotation dropped 210 rows
- A **long exception message on a single line**, as .NET actually writes it

| File | Failure | Needs the screenshot? |
|---|---|---|
| `log_A_selector_not_found.log` | Selector fails after 3 retries mid-batch (row 213 of 318) | **Yes** — what was on screen decides it |
| `log_B_excel_com_timeout.log` | Excel COM hang, wrapped in a retry `ActivityException` | No — a log-and-code diagnosis |
| `log_C_credential_expired.log` | Service credential past max age, rejected with HTTP 401 | No |

---

## What these already changed in the design

Running the documented fingerprint over them found three defects. All were in `DATA_MODEL.md`, all
would have shipped, and none were visible against the tidier generated fixtures.

**1. Fingerprinting on the wrong exception type.** iBot wraps retried activities, so `log_B` reports
`iBot.Core.ActivityException ---> System.Runtime.InteropServices.COMException`. The documented rule
took the outer type — which would have made *every retry-wrapped failure in the estate* the same
exception type. An Excel COM hang and a locked-file `IOException` become indistinguishable. Since
most activities that touch a UI or a file sit inside a `RetryScope`, this would have flattened a
large share of all failures into one bucket. Fixed: unwrap the chain, fingerprint the innermost type
(`DATA_MODEL.md` §2.2a).

**2. The `0x…` rule destroyed HRESULTs.** `COMException (0x800A03EC)` (Excel busy with an OLE action)
and `COMException (0x80010105)` (server threw an exception) are different faults with different
fixes. Normalizing `0x…` to `<ADDR>` merged them. COM errors are common in RPA precisely because RPA
drives Office and legacy desktop apps through that interface. Fixed: match bare addresses narrowly,
never touch `ExceptionName (0x…)`.

**3. CRLF rode into the hash.** `split("\n")` strands `\r` on every line, and a regex capturing to
end-of-line captures it, so the hashed message was `"…boom\r"`. The same failure read on two
platforms fingerprinted differently. Fixed: normalize line endings before anything else.

The pattern is worth noting: the earlier generated fixtures were *too clean*, so they exercised the
mechanism but not the format. Realistic mess is where parser bugs live.

---

## What would make these obsolete

**One real log file, sanitized by hand, reviewed before it leaves the estate**
(`OPEN_QUESTIONS.md` D1). One file, once — the permitted exception in `SECURITY.md` §11.

The specific things it would settle, none of which can be guessed:

1. Timestamp format, log level names, and whether there is a thread or component field
2. Whether stack traces are present at all, and in .NET format
3. How the screenshot filename relates to the log's run ID — **the pairing question**
   (`OPEN_QUESTIONS.md` D5), which decides whether screenshots can be attached reliably
4. Whether retries appear as separate log lines or only as a final count
5. Encoding — UTF-8, UTF-16, or a Windows code page

Item 3 is the one with a design consequence rather than a parsing consequence. The rest change
regexes; that one changes whether the vision input works.
