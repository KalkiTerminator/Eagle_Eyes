"""The known-pattern library: what it matches, what it refuses, what it costs."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.analysis import Engine, FAILURE_TYPES, SEVERITIES, Path_  # noqa: E402
from eagle_eyes.model_gateway import MODELS, MockBackend  # noqa: E402
from eagle_eyes.patterns import (  # noqa: E402
    LIBRARY_PATH, TEMPLATE_CONFIDENCE, PatternError, PatternLibrary,
    load_patterns, to_row,
)
from eagle_eyes.storage import (  # noqa: E402
    ADMIN, Database, PatternRepo, Principal,
)

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check

LIB = PatternLibrary.from_file()


def _db():
    d = Path(tempfile.mkdtemp())
    return Database(d / "t.db"), d


# ------------------------------------------------------------------ the file

def test_the_shipped_library_loads_and_is_well_formed() -> None:
    check("the library is not empty", len(LIB) > 0, str(len(LIB)))
    for p in LIB.patterns:
        check(f"{p.name}: failure_type is in the closed list",
              p.failure_type in FAILURE_TYPES, p.failure_type)
        check(f"{p.name}: severity is in the closed list",
              p.severity in SEVERITIES, p.severity)
        check(f"{p.name}: needs both axes to match",
              bool(p.exception_any) and bool(p.message_any))
        check(f"{p.name}: the fix says what to change",
              len(p.suggested_fix) > 60, str(len(p.suggested_fix)))


def test_the_fixes_are_written_for_the_estate_that_runs_them() -> None:
    """The kit these came from is written for Python and `requests`.

    Our fixtures, our prompts and the whole product are C#/.NET and Selenium. A
    fix that tells a .NET developer to use `requests.adapters.HTTPAdapter` is
    not merely unhelpful -- it reads as obviously machine-generated and takes
    the credibility of every other answer down with it.
    """
    # Against the loaded patterns, not the file. The file's own commentary
    # explains WHY a `requests`/urllib3 fix would be wrong, and a test that
    # greps the whole file fails on the sentence saying so -- the same trap the
    # PostgreSQL schema tests strip comments to avoid.
    joined = " ".join(f"{p.root_cause} {p.suggested_fix}" for p in LIB.patterns)
    lowered = joined.lower()
    for wrong in ("requests.adapters", "urllib3", "time.sleep", "path.exists()",
                  "requests_ca_bundle", "python", "pip install"):
        check(f"no Python idiom: {wrong}", wrong not in lowered)

    for expected in ("HttpClient", "WebDriverWait", "Polly", "ChromeOptions"):
        check(f"the fixes speak .NET: {expected}", expected in joined)


def test_a_bad_entry_stops_the_load_rather_than_narrowing_the_library() -> None:
    """A library that silently drops a broken entry looks complete and quietly
    escalates everything that entry was meant to catch."""
    base = json.loads(LIBRARY_PATH.read_text())["patterns"][0]

    def load(mutate) -> str:
        entry = dict(base)
        entry["match_rule"] = dict(base["match_rule"])
        mutate(entry)
        d = Path(tempfile.mkdtemp())
        try:
            f = d / "p.json"
            f.write_text(json.dumps({"patterns": [entry]}))
            try:
                load_patterns(f)
            except PatternError as e:
                return str(e)
            return ""
        finally:
            shutil.rmtree(d, ignore_errors=True)

    cases = [
        ("an exception list with no message list",
         lambda e: e["match_rule"].update(message_any=[])),
        ("a message list with no exception list",
         lambda e: e["match_rule"].update(exception_any=[])),
        ("an unknown failure_type", lambda e: e.update(failure_type="vibes")),
        ("an unknown severity", lambda e: e.update(severity="spicy")),
        ("no name", lambda e: e.update(name="")),
        ("no suggested_fix", lambda e: e.update(suggested_fix="  ")),
    ]
    for label, mutate in cases:
        check(f"refused: {label}", bool(load(mutate)))


def test_duplicate_names_are_refused() -> None:
    entry = json.loads(LIBRARY_PATH.read_text())["patterns"][0]
    d = Path(tempfile.mkdtemp())
    try:
        f = d / "p.json"
        f.write_text(json.dumps({"patterns": [entry, dict(entry)]}))
        try:
            load_patterns(f)
            check("a duplicate name is refused", False)
        except PatternError as e:
            check("a duplicate name is refused", "duplicate" in str(e))
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------------- the matcher

def test_the_exception_class_is_matched_exactly_not_as_a_substring() -> None:
    """`WebDriverTimeoutException` is a selector problem wearing a timeout's
    name. A substring match on "TimeoutException" gives it the timeout fix --
    raise HttpClient.Timeout -- for a page whose button moved."""
    timeout = LIB.match("System.TimeoutException", "The operation has timed out.")
    selector = LIB.match("OpenQA.Selenium.WebDriverTimeoutException",
                         "Timed out after 10 seconds")
    check("System.TimeoutException is a timeout",
          timeout is not None and timeout.name == "timeout",
          timeout.name if timeout else "no match")
    check("WebDriverTimeoutException is a selector failure",
          selector is not None and selector.name == "selector_not_found",
          selector.name if selector else "no match")


def test_one_exception_class_routes_by_its_message() -> None:
    """HttpRequestException covers 401, 429, DNS failure and a TLS error. The
    class alone cannot choose between four different fixes."""
    cases = [
        ("Response status code does not indicate success: 401 (Unauthorized).",
         "auth_expired"),
        ("Response status code does not indicate success: 429 (Too Many Requests).",
         "rate_limited"),
        ("No such host is known. (polcore.internal:443)", "network_error"),
        ("The SSL connection could not be established: the remote certificate is"
         " invalid according to the validation procedure.", "ssl_error"),
    ]
    for message, want in cases:
        got = LIB.match("System.Net.Http.HttpRequestException", message)
        check(f"{want} from its message", got is not None and got.name == want,
              got.name if got else "no match")


def test_the_message_alone_is_never_enough() -> None:
    """A message that reads like a known pattern, thrown by a class the pattern
    does not cover, is not a match. It goes to a real analysis."""
    got = LIB.match("System.NullReferenceException",
                    "Object reference not set to an instance of an object.")
    check("an unrecognised failure gets no template", got is None,
          got.name if got else "")
    got = LIB.match("Finance.AP.LedgerOutOfBalanceException",
                    "Ledger did not balance: 429 lines posted, 428 expected.")
    check("a domain exception is not rate-limited by a coincidence in its text",
          got is None, got.name if got else "")


def test_exclude_disqualifies_a_lookalike() -> None:
    got = LIB.match("System.Net.Http.HttpRequestException",
                    "401 Unauthorized -- too many requests, slow down")
    check("wording that names two patterns takes the one that did not exclude it",
          got is not None and got.name == "rate_limited",
          got.name if got else "no match")


# ---------------------------------------------------------------- the engine

def _engine(library: PatternLibrary) -> tuple[Engine, MockBackend]:
    backend = MockBackend()
    return Engine(backend, MODELS["mock"], library=library), backend


LOG = """12-09-2026 03:38:00.000 [ERROR] Activity 'PostSingleRemittance' failed
12-09-2026 03:38:00.000 [ERROR] OpenQA.Selenium.NoSuchElementException: no such \
element: Unable to locate element: {"method":"id","selector":"btnPost"}
   at OpenQA.Selenium.WebDriver.Execute(String cmd, Dictionary`2 parameters)
   at iBot.Processes.AP.PostInvoice(String ref) in C:\\ibot\\AP.cs:line 119
"""


def test_a_known_pattern_is_answered_without_a_model_call() -> None:
    engine, backend = _engine(LIB)
    a = engine.analyse(log_text=LOG, code_text="", code_path="", code_mtime=None,
                       code_stale=False, bot_label="FINANCE_AP/BOT201",
                       code_location="AP.cs:PostInvoice", image=None)
    check("no model was called at all", backend.calls == [], str(backend.calls))
    check("it costs nothing", sum(u.cost_usd for u in a.usages) == 0.0)
    check("recorded as a template answer", a.path == Path_.TEMPLATE.value, a.path)
    check("and routed as a known pattern", a.category == "known_pattern", a.category)
    check("it carries the taxonomy the pattern declares",
          (a.failure_type, a.severity) == ("selector", "high"),
          str((a.failure_type, a.severity)))
    check("the fix is the .NET one", "WebDriverWait" in a.suggested_fix)
    check("and it says it is a library answer, not a diagnosis of this failure",
          "library" in a.notes.lower() and "not a diagnosis" in a.notes.lower(),
          a.notes)


def test_a_template_is_less_confident_than_a_real_analysis() -> None:
    """It is the standard fix for failures of this CLASS, unverified against
    this one. Presenting it at the confidence of a real diagnosis would be the
    system overstating what it did."""
    engine, _ = _engine(LIB)
    a = engine.analyse(log_text=LOG, code_text="", code_path="", code_mtime=None,
                       code_stale=False, bot_label="B", code_location="AP.cs:P",
                       image=None)
    check("a template answer is 0.6", abs(a.confidence - TEMPLATE_CONFIDENCE) < 1e-9,
          str(a.confidence))
    check("which is below the band a clear diagnosis reaches",
          TEMPLATE_CONFIDENCE < 0.8, str(TEMPLATE_CONFIDENCE))


def test_an_empty_library_escalates_rather_than_guessing() -> None:
    engine, backend = _engine(PatternLibrary.empty())
    a = engine.analyse(log_text=LOG, code_text="", code_path="", code_mtime=None,
                       code_stale=False, bot_label="B", code_location="AP.cs:P",
                       image=None)
    check("with no library, nothing is answered from one",
          a.path != Path_.TEMPLATE.value, a.path)
    check("and the model was reached for", backend.calls != [])


# ------------------------------------------------------------ the table

def test_the_table_is_what_the_engine_reads() -> None:
    db, d = _db()
    try:
        p = Principal("tester", ADMIN)
        repo = PatternRepo(db, p)
        added = repo.sync()
        check("the shipped library lands in the table", added == len(LIB), str(added))
        check("syncing again adds nothing", repo.sync() == 0)
        check("and the table round-trips to the same matcher",
              repo.library().names() == LIB.names(), str(repo.library().names()))

        repo.set_active("selector_not_found", False)
        lib = repo.library()
        check("a deactivated pattern leaves the matcher",
              "selector_not_found" not in lib.names(), str(lib.names()))
        check("  and the failure it covered now gets a real analysis",
              lib.match("OpenQA.Selenium.NoSuchElementException",
                        "Unable to locate element") is None)

        repo.sync()
        check("a later boot does not switch it back on",
              "selector_not_found" not in repo.library().names(),
              str(repo.library().names()))

        n = db.conn.execute("SELECT COUNT(*) n FROM audit_event"
                            " WHERE resource_type='pattern'").fetchone()["n"]
        check("every change to the library is audited", n >= 3, str(n))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_row_survives_the_round_trip_intact() -> None:
    """`to_row` and `from_rows` are inverses. If they are not, a pattern behaves
    one way from the file and another way from the database, and only the
    deployed instance sees the second."""
    from eagle_eyes.patterns import from_rows

    class _Row(dict):
        def __getitem__(self, k):
            return dict.__getitem__(self, k)

    rows = [_Row(to_row(p)) for p in LIB.patterns]
    back = from_rows(rows)
    check("the same patterns, in the same order", back.names() == LIB.names())
    for a, b in zip(LIB.patterns, back.patterns):
        check(f"{a.name} survives", (a.failure_type, a.severity, a.root_cause,
                                     a.suggested_fix, a.exception_any,
                                     a.message_any, a.exclude_any)
              == (b.failure_type, b.severity, b.root_cause, b.suggested_fix,
                  b.exception_any, b.message_any, b.exclude_any))


# ------------------------------------------------------ caps vs projections

def test_the_hosted_caps_permit_the_call_they_govern() -> None:
    """A per-call cap below the per-call projection refuses everything.

    `DEFAULT_SINGLE_CALL` was 0.05 and a deep call is projected at 0.06, so the
    hosted instance refused every deep analysis before attempting it -- with a
    valid key, an untouched budget, and the message "single call projected at
    $0.0600, cap is $0.05". Nothing failed: the guard did exactly what it was
    told, and what it was told was wrong. Two constants in two files, and no
    test between them.
    """
    from eagle_eyes.analysis import DEEP_PROJECTION_USD, TRIAGE_PROJECTION_USD
    from eagle_eyes.model_gateway import BudgetGuard
    from eagle_eyes.web import spend

    check("the single-call cap admits a deep call",
          spend.DEFAULT_SINGLE_CALL >= DEEP_PROJECTION_USD,
          f"{spend.DEFAULT_SINGLE_CALL} < {DEEP_PROJECTION_USD}")
    check("  and a triage call", spend.DEFAULT_SINGLE_CALL >= TRIAGE_PROJECTION_USD)
    check("the per-run cap admits at least one whole analysis",
          spend.DEFAULT_PER_RUN >= TRIAGE_PROJECTION_USD + DEEP_PROJECTION_USD)
    check("and the daily cap admits at least one run",
          spend.DEFAULT_DAILY >= spend.DEFAULT_PER_RUN)

    # Not only arithmetic: run one through the guard the hosted app builds.
    engine = Engine(MockBackend(), MODELS["mock"], library=PatternLibrary.empty(),
                    budget=BudgetGuard(daily_usd=spend.DEFAULT_DAILY,
                                       per_run_usd=spend.DEFAULT_PER_RUN,
                                       single_call_usd=spend.DEFAULT_SINGLE_CALL,
                                       total_usd=spend.DEFAULT_TOTAL))
    a = engine.analyse(log_text=LOG, code_text="public void PostInvoice() {}",
                       code_path="AP.cs", code_mtime=None, code_stale=False,
                       bot_label="B", code_location="AP.cs:P", image=None)
    check("a novel failure reaches the model under the hosted defaults",
          a.path == Path_.TEXT.value, f"{a.path}: {a.notes}")


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
