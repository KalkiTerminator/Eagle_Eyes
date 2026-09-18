"""Populating a fresh deployment so it has something to show.

Two demonstrations, and they are the two claims worth making:

  1. THE DIAGNOSIS IS REAL. A handful of failures are analysed through the same
     engine, prompts and provider a deployment would use. Nothing is canned.

  2. THE DEDUP ECONOMICS ARE REAL. One spike -- two hundred failures from a
     single cause, which is what an infrastructure incident actually looks like
     -- collapses to one fingerprint and one analysis. The cost counter on the
     home page is the argument.

Everything here is fabricated. tools/make_fixtures.py writes it and says so on
every file. Nothing in this module reads a share, a client log or anything a
real estate produced -- which is the entire reason it is safe for this to be a
public URL.

Seeding runs once. A deployment that reseeded on every boot would re-spend on
every redeploy, which is exactly the kind of quiet recurring cost the budget
caps exist to catch.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..discovery import discover
from ..storage import (
    ADMIN, AnalysisRepo, BotRepo, DeveloperRepo, FailureRepo, FingerprintRepo,
    Principal, now,
)

SEED_VAR = "EAGLE_EYES_SEED"
SEED_ACTOR = "seed"
DEMO_OWNER = "demo@eagle-eyes.invalid"

# How many distinct failures to analyse for real. Small on purpose: each one is
# a paid call, and the point is made by a handful plus the spike.
DEFAULT_REAL_ANALYSES = 6


def seed_wanted(env: dict[str, str] | None = None) -> bool:
    env = env if env is not None else os.environ
    return (env.get(SEED_VAR, "") or "").strip().lower() in ("1", "true", "yes", "on")


def already_seeded(db) -> bool:
    return bool(db.conn.execute(
        "SELECT 1 FROM audit_event WHERE action='seed' LIMIT 1").fetchone())


def seed_if_asked(db, engine_factory, env: dict[str, str] | None = None) -> dict | None:
    """Seed when EAGLE_EYES_SEED is set and the database is empty.

    Returns a summary, or None when there was nothing to do. Never raises into
    start-up: a deployment that will not boot because the demo data failed is
    worse than a deployment with no demo data.
    """
    env = env if env is not None else dict(os.environ)
    if not seed_wanted(env):
        return None
    if already_seeded(db):
        return None
    try:
        return seed(db, engine_factory,
                    real_analyses=int(env.get("EAGLE_EYES_SEED_ANALYSES",
                                              DEFAULT_REAL_ANALYSES)))
    except Exception as exc:                      # pragma: no cover - defensive
        print(f"  ! seeding failed ({exc}); the app is running without demo data",
              flush=True)
        return None


def seed(db, engine_factory, *, real_analyses: int = DEFAULT_REAL_ANALYSES) -> dict:
    """Generate fixtures, analyse a few for real, and record the spike."""
    # tools/ is not part of the installed package, so it is loaded by path.
    # The generator is a development tool and stays one -- it is not something a
    # deployment should be able to point at a directory.
    generate = _load_generator()

    p = Principal(actor=SEED_ACTOR, role=ADMIN)
    root = Path(tempfile.mkdtemp(prefix="eagle-eyes-seed-"))
    generate(root, 42, 3)

    share = root / "Network_Sharing_Folder"
    code = root / "code_folder"
    candidates = discover(share, share, code)

    devs = DeveloperRepo(db, p)
    devs.ensure(DEMO_OWNER, display_name="Demo")

    engine = engine_factory()

    # TWO PASSES, and the reason is the whole demonstration.
    #
    # Fingerprint everything first, then decide where the analysis budget goes.
    # Analysing whichever failures happen to come first spends six calls on six
    # one-off problems and leaves the two-hundred-failure spike -- the case the
    # product exists for -- showing as unanalysed.
    #
    # The budget is only spent on fingerprints the known-pattern library does
    # NOT answer. A template costs nothing, so every failure the library covers
    # is answered regardless; ranking by occurrence alone would spend all six
    # calls on the biggest spikes, which are exactly the ones already free, and
    # leave the failures that genuinely need a model showing as pending. The
    # remaining budget goes to the most frequent of those.
    prints, free = _fingerprint_all(candidates, getattr(engine, "library", None))
    ranked = sorted(((h, paths) for h, paths in prints.items() if h not in free),
                    key=lambda kv: len(kv[1]), reverse=True)
    chosen = free | {h for h, _ in ranked[:real_analyses]}
    seen: dict[str, int] = {}
    summary = {"failures": 0, "analysed": 0, "deduped": 0, "unanalysed": 0,
               "cost_usd": 0.0, "fingerprints": len(prints)}

    for candidate in candidates:
        fp_hash = prints_of(prints, candidate)
        if fp_hash is None:
            continue
        _store(db, p, candidate, engine, fp_hash, fp_hash in chosen, seen, summary)

    db.conn.execute(
        "INSERT INTO audit_event(actor, actor_role, action, resource_type,"
        " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
        (SEED_ACTOR, ADMIN, "seed", "database", "-", "allow", now()))
    print(f"  seeded: {summary['failures']} failures in "
          f"{summary['fingerprints']} distinct fingerprints, "
          f"{summary['analysed']} analysed for real, "
          f"{summary['deduped']} answered from the store, "
          f"{summary['unanalysed']} left pending, "
          f"${summary['cost_usd']:.4f} spent", flush=True)
    return summary


def _load_generator():
    """tools/make_fixtures.generate, loaded from the repository next to us."""
    import importlib.util
    here = Path(__file__).resolve()
    path = here.parents[2] / "tools" / "make_fixtures.py"
    if not path.is_file():
        raise FileNotFoundError(
            f"{path} is missing. Seeding needs the fixture generator, which "
            "ships with the repository but not with the installed package.")
    spec = importlib.util.spec_from_file_location("ee_make_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.generate


def _fingerprint_all(candidates, library=None) -> tuple[dict[str, list], set[str]]:
    """Every candidate's fingerprint, grouped, and which the library answers.

    Both are free -- no model is involved in either. Knowing which fingerprints
    a template covers is what lets the analysis budget go where it is actually
    needed.
    """
    from ..discovery import read_text
    from ..fingerprint import fingerprint
    from ..sanitize import sanitize_log

    out: dict[str, list] = {}
    free: set[str] = set()
    for candidate in candidates:
        result = fingerprint(sanitize_log(read_text(candidate.log_path)).text,
                             str(candidate.code_path or ""))
        if result is None:
            continue
        fp_hash, failure = result
        out.setdefault(fp_hash, []).append(candidate.log_path)
        if library is not None and library.match(failure.exception_type,
                                                 failure.message):
            free.add(fp_hash)
    return out, free


def prints_of(prints: dict[str, list], candidate) -> str | None:
    for fp_hash, paths in prints.items():
        if candidate.log_path in paths:
            return fp_hash
    return None


def _store(db, p, candidate, engine, fp_hash: str, may_analyse: bool,
           seen: dict[str, int], summary: dict) -> None:
    """One fixture failure, stored the way the scanner would store it."""
    from ..discovery import read_text

    log_text = read_text(candidate.log_path)
    code_text = read_text(candidate.code_path) if candidate.code_path else ""

    bots = BotRepo(db, p)
    bot_id = bots.upsert(candidate.location.service_line,
                         candidate.location.bot_number,
                         str(candidate.code_path) if candidate.code_path else None)
    bots.set_owner(bot_id, DEMO_OWNER)
    bots.set_team(bot_id, candidate.location.service_line)

    fp_id = FingerprintRepo(db, p).touch(
        fp_hash, 1, candidate.exception_type or "Unknown",
        candidate.message or "", str(candidate.code_path or ""))

    known = fp_hash in seen
    analysis_id = seen.get(fp_hash)

    if not known and may_analyse:
        analysis = engine.analyse(
            log_text=log_text, code_text=code_text,
            code_path=str(candidate.code_path or ""),
            code_mtime=(candidate.code_mtime.isoformat(timespec="seconds")
                        if candidate.code_mtime else None),
            code_stale=candidate.code_possibly_stale,
            bot_label=candidate.location.label,
            code_location=str(candidate.code_path or ""),
            image=None)                   # Mode 0: the image is never read here
        cost = sum(u.cost_usd for u in analysis.usages if u.priced)
        analysis_id = AnalysisRepo(db, p).add(
            fp_id, path=analysis.path, root_cause=analysis.root_cause,
            suggested_fix=analysis.suggested_fix, confidence=analysis.confidence,
            model_id=(analysis.usages[-1].model if analysis.usages else ""),
            inputs_used=tuple(analysis.inputs_used),
            tokens_in=sum(u.input_tokens for u in analysis.usages),
            tokens_out=sum(u.output_tokens for u in analysis.usages),
            cost_usd=cost,
            latency_ms=sum(u.latency_ms for u in analysis.usages),
            cache_read_tokens=sum(u.cache_read_tokens for u in analysis.usages),
            image_tokens=sum(u.image_tokens for u in analysis.usages),
            category=analysis.category,
            failure_type=analysis.failure_type, severity=analysis.severity,
            affected_function=analysis.affected_function,
            recommendations=analysis.recommendations)
        seen[fp_hash] = analysis_id
        summary["analysed"] += 1
        summary["cost_usd"] += cost

    status = "deduped" if known else ("analyzed" if analysis_id else "pending")

    failure_id = FailureRepo(db, p).add(
        bot_id=bot_id, fingerprint_id=fp_id, analysis_id=analysis_id,
        occurred_at=(candidate.occurred_at or datetime.now(timezone.utc)).replace(
            tzinfo=None).isoformat(timespec="seconds"),
        log_path=str(candidate.log_path),
        screenshot_path=(str(candidate.screenshot_path)
                         if candidate.screenshot_path else None),
        code_path=str(candidate.code_path) if candidate.code_path else None,
        code_possibly_stale=candidate.code_possibly_stale,
        pairing_method=candidate.pairing_method,
        log_sanitized=log_text[:20000],
        was_deduped=known,
        correlation_id="seed",
        status=status)

    if failure_id is None:
        return
    summary["failures"] += 1
    if known:
        summary["deduped"] += 1
    elif analysis_id is None:
        # Outside the analysis budget: stored, fingerprinted, and honestly
        # marked pending rather than given a diagnosis nobody paid for.
        summary["unanalysed"] += 1
