"""Entry point.

  Pick a folder in a dialog and review before running:
      python -m eagle_eyes --pick-folder

  Pick one log file:
      python -m eagle_eyes --pick-file

  Point at a path directly (no dialog):
      python -m eagle_eyes --target "\\\\VM\\Network_Sharing_Folder\\data\\FINANCE_AP\\BOT201"

  Unattended, for the scheduler -- no prompts, runs whatever it finds:
      python -m eagle_eyes --target <path> --yes

Discovery is read-only and costs nothing, so --dry-run shows exactly what
would be analysed without touching a model.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .analysis import Engine
from .cache import SharedCache
from .discovery import discover, read_text
from .doctor import report as doctor_report, run_checks
from .model_gateway import BudgetGuard, create_backend, models_for
from .notify import Notifier, compose
from .report import ReportInput, write, write_index
from .runtime import describe_host, resolve_paths
from .storage import (AnalysisRepo, BotRepo, Database, FailureRepo,
                      FingerprintRepo, Principal, WatermarkRepo, run_retention)
from .selection import estimate_cost, pick_file, pick_folder, review


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="eagle_eyes", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pick-folder", action="store_true", help="choose a folder in a dialog")
    src.add_argument("--pick-file", action="store_true", help="choose one log file in a dialog")
    src.add_argument("--target", type=Path, help="analyse this file or folder directly")

    ap.add_argument("--share-root", type=Path,
                    help="root containing data/<service line>/...")
    ap.add_argument("--code-root", type=Path, help="folder of bot code files")
    ap.add_argument("--yes", action="store_true",
                    help="skip the review and run everything found (for the scheduler)")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be analysed, then stop")
    ap.add_argument("--backend", default="mock", choices=["mock", "bedrock", "byok"],
                    help="mock costs nothing and needs no credentials (default)")
    ap.add_argument("--region", default="", help="AWS region, for the bedrock backend")
    ap.add_argument("--screenshot-mode", type=int, default=0, choices=[0, 3],
                    help="0 = never send a screenshot to a model (default); "
                         "3 = send it as captured, uncropped and unredacted. "
                         "Modes 1 and 2 (crop, OCR-redact) are designed but not built; "
                         "see docs/SECURITY.md section 7")
    ap.add_argument("--shared-cache", type=Path,
                    help="directory every install can reach, for shared dedup")
    ap.add_argument("--budget", type=float, default=2.00,
                    help="stop this run once it would exceed this many dollars")
    ap.add_argument("--db", type=Path,
                    help="database file (default: the platform data directory)")
    ap.add_argument("--rescan", action="store_true",
                    help="re-read logs already processed, ignoring the watermark")
    ap.add_argument("--retention", action="store_true",
                    help="apply the retention policy and exit")
    ap.add_argument("--stats", action="store_true",
                    help="show what this database holds and exit")
    ap.add_argument("--doctor", action="store_true",
                    help="check whether this machine can run it, and exit")
    ap.add_argument("--reports", type=Path,
                    help="folder for HTML reports (default: the platform data directory)")
    ap.add_argument("--no-reports", action="store_true", help="skip writing reports")
    ap.add_argument("--notify", metavar="EMAIL",
                    help="email the developer responsible (suppression always applies)")
    ap.add_argument("--smtp-host", default="",
                    help="mail relay; without it notifications are rendered, not sent")
    args = ap.parse_args(argv)

    # --doctor runs before anything else touches a path or opens a database:
    # its whole job is to report on a machine that may not be set up yet.
    if args.doctor:
        return doctor_report(run_checks(args.share_root, args.code_root))

    if not args.share_root or not args.code_root:
        ap.error("--share-root and --code-root are required "
                 "(run --doctor first if you are setting up)")

    principal = Principal.local()
    db = Database(args.db or resolve_paths().ensure().database)

    if args.retention:
        r = run_retention(db, principal)
        print(f"Retention applied to {db.path}\n  {r.summary()}")
        return 0

    if args.stats:
        fr = FailureRepo(db, principal)
        s_ = fr.stats()
        print(f"{db.path}")
        print(f"  {s_['failures']} failures, {s_['fingerprints']} distinct fingerprints")
        print(f"  dedup rate {s_['dedup_rate']:.1%}, ${s_['spend_usd']:.4f} spent to date")
        print(f"  {WatermarkRepo(db, principal).count()} files already processed")
        for row in fr.recent(10):
            conf = f"{row['confidence']:.2f}" if row["confidence"] is not None else " -- "
            print(f"    {row['occurred_at'][:16]}  {row['service_line']}/{row['bot_number']:<8}"
                  f"  conf {conf}  {(row['root_cause'] or '(not analysed)')[:54]}")
        return 0

    if args.pick_folder:
        target = pick_folder("Select a folder to analyse", initial=args.share_root)
    elif args.pick_file:
        target = pick_file("Select a log file", initial=args.share_root)
    elif args.target:
        target = args.target
    else:
        # No source given: offer the choice rather than failing on usage.
        print("\nWhat do you want to analyse?")
        print("  1. a folder  (a date, a bot, or a whole service line)")
        print("  2. a single log file")
        pick = input("  [1/2, or q to quit]: ").strip()
        if pick == "1":
            target = pick_folder("Select a folder to analyse", initial=args.share_root)
        elif pick == "2":
            target = pick_file("Select a log file", initial=args.share_root)
        else:
            return 0

    if target is None:
        print("Nothing selected.")
        return 0

    print(f"\nScanning {target} ...")
    try:
        cands = discover(target, args.share_root, args.code_root)
    except FileNotFoundError:
        print(f"  ! not found: {target}")
        return 2

    marks = WatermarkRepo(db, principal)
    if not args.rescan:
        before = len(cands)
        cands = [c for c in cands
                 if not marks.seen(str(c.log_path),
                                   str(c.log_path.stat().st_mtime),
                                   c.log_path.stat().st_size)]
        if before != len(cands):
            print(f"  {before - len(cands)} already processed "
                  f"(use --rescan to re-read them)")

    if not cands:
        print("  No failure logs found there.")
        print("  (Logs are expected under .../logs/user logs/logs/ inside the share root,")
        print("   and already-processed files are skipped unless --rescan is given.)")
        return 0

    chosen = review(cands, args.code_root, interactive=not (args.yes or args.dry_run))

    if args.dry_run:
        total, parts = estimate_cost(cands)
        print(f"\nDry run: {parts['selected']} would be analysed, "
              f"up to ${total:,.2f} if nothing dedups. Nothing was sent.")
        return 0

    if not chosen:
        return 0

    # ---- analyse ----------------------------------------------------
    try:
        # The environment is derived, never asserted here. Hardcoding "local"
        # meant the byok governance guard could not fire on a deployed host --
        # a guard that silently never runs (model_gateway.current_environment).
        backend = create_backend(
            {"backend": args.backend, "region": args.region})
    except Exception as exc:
        print(f"\n  ! {exc}")
        return 3

    cache = SharedCache(args.shared_cache, written_by=describe_host()["machine"]) \
        if args.shared_cache else None
    if cache and not cache.available:
        print(f"\n  note: {cache.reason}")

    engine = Engine(
        backend, models_for(backend.name),
        budget=BudgetGuard(daily_usd=args.budget, per_run_usd=args.budget,
                           single_call_usd=max(args.budget / 4, 0.05)),
        cache=cache, screenshot_mode=args.screenshot_mode)

    print(f"\nAnalysing {len(chosen)} failures via {backend.name}"
          f"{' (no model call, no cost)' if backend.name == 'mock' else ''} ...\n")

    report_dir = args.reports or resolve_paths().ensure().reports
    notifier = Notifier(dry_run=not args.smtp_host, smtp_host=args.smtp_host)
    written: list[tuple[ReportInput, Path]] = []
    results = []
    for i, c in enumerate(chosen, 1):
        image = None
        if c.screenshot_path and c.send_screenshot and args.screenshot_mode > 0:
            try:
                image = c.screenshot_path.read_bytes()
            except OSError:
                image = None
        a = engine.analyse(
            log_text=read_text(c.log_path),
            code_text=read_text(c.code_path) if c.code_path else "",
            code_path=str(c.code_path or ""),
            code_mtime=c.code_mtime.isoformat() if c.code_mtime else None,
            code_stale=c.code_possibly_stale,
            bot_label=c.location.label,
            code_location=f"{c.location.bot_number}:{c.exception_type}",
            image=image, force=c.force_reanalyze)
        # Persist. A failed write must not lose the diagnosis already produced,
        # so it is reported and the run continues.
        try:
            with db.tx():
                bot_id = BotRepo(db, principal).upsert(
                    c.location.service_line, c.location.bot_number,
                    str(c.code_path) if c.code_path else None)
                fp_id = FingerprintRepo(db, principal).touch(
                    a.fingerprint or "0" * 64, 1, c.exception_type,
                    a.root_cause[:500], f"{c.location.bot_number}:{c.exception_type}")
                analysis_id = None
                if a.path not in ("dedup", "skipped"):
                    analysis_id = AnalysisRepo(db, principal).add(
                        fp_id, path=a.path, root_cause=a.root_cause,
                        suggested_fix=a.suggested_fix, confidence=a.confidence,
                        model_id=a.model_id,
                        code_mtime=c.code_mtime.isoformat() if c.code_mtime else None,
                        inputs_used=a.inputs_used,
                        tokens_in=sum(u.input_tokens for u in a.usages),
                        tokens_out=sum(u.output_tokens for u in a.usages),
                        cost_usd=a.cost_usd, latency_ms=a.latency_ms,
                        failure_type=a.failure_type, severity=a.severity,
                        affected_function=a.affected_function,
                        recommendations=a.recommendations)
                FailureRepo(db, principal).add(
                    bot_id=bot_id, fingerprint_id=fp_id,
                    occurred_at=(c.occurred_at or datetime.now()).isoformat(timespec="seconds"),
                    log_path=str(c.log_path), analysis_id=analysis_id,
                    screenshot_path=str(c.screenshot_path) if c.screenshot_path else None,
                    code_path=str(c.code_path) if c.code_path else None,
                    code_mtime=c.code_mtime.isoformat() if c.code_mtime else None,
                    code_possibly_stale=c.code_possibly_stale,
                    pairing_method=c.pairing_method,
                    was_deduped=(a.path == "dedup"),
                    status="analyzed" if a.confidence > 0 else "failed")
                st = c.log_path.stat()
                marks.mark(str(c.log_path), str(st.st_mtime), st.st_size)
        except Exception as exc:
            print(f"        ! not saved: {exc}")

        # Report first: it is what reaches anyone who did not run this.
        if not args.no_reports:
            try:
                ri = ReportInput(
                    bot_label=c.location.label,
                    occurred_at=(c.occurred_at or datetime.now()).isoformat(timespec="seconds"),
                    exception_type=c.exception_type or "(unparsed)",
                    root_cause=a.root_cause, suggested_fix=a.suggested_fix,
                    confidence=a.confidence, path=a.path, category=a.category,
                    notes=a.notes, inputs_used=a.inputs_used,
                    log_path=str(c.log_path),
                    screenshot_path=str(c.screenshot_path) if c.screenshot_path else "",
                    pairing_method=c.pairing_method,
                    code_path=str(c.code_path) if c.code_path else "",
                    code_possibly_stale=c.code_possibly_stale,
                    model_id=a.model_id,
                    cost_usd=a.cost_usd if a.fully_priced else None)
                rp = write(ri, report_dir,
                           f"{c.location.bot_number}_{ri.occurred_at.replace(':', '-')}")
                written.append((ri, rp))
                if args.notify:
                    notifier.send(
                        compose(to=args.notify, bot_label=ri.bot_label,
                                exception_type=ri.exception_type,
                                root_cause=a.root_cause, suggested_fix=a.suggested_fix,
                                confidence=a.confidence, fingerprint=a.fingerprint,
                                report_path=rp),
                        category=a.category, confidence=a.confidence)
            except Exception as exc:
                print(f"        ! no report: {exc}")

        results.append((c, a))
        cost = f"${a.cost_usd:.4f}" if a.fully_priced else "cost unknown"
        print(f"  [{i}/{len(chosen)}] {c.location.label}  {a.path:<9} "
              f"conf {a.confidence:.2f}  {cost}")
        print(f"        {a.root_cause[:96]}")

    spent = sum(a.cost_usd for _, a in results)
    unpriced = sum(1 for _, a in results if not a.fully_priced and a.usages)
    by_path: dict[str, int] = {}
    for _, a in results:
        by_path[a.path] = by_path.get(a.path, 0) + 1
    print(f"\n  {len(results)} analysed, ${spent:.4f} spent"
          + (f"  (+{unpriced} with no known rate -- not counted)" if unpriced else ""))
    print("  " + ", ".join(f"{n} {p}" for p, n in sorted(by_path.items())))
    if cache:
        print(f"  {cache.summary()}")
    print(f"  saved to {db.path}  (--stats to review, --retention to apply the policy)")
    if written:
        idx = write_index(written, report_dir)
        print(f"  {len(written)} reports in {report_dir}")
        print(f"  index: {idx}")
    if args.notify:
        verb = "sent" if args.smtp_host else "rendered (no relay configured)"
        print(f"  {len(notifier.sent_log)} notifications {verb}")
        if notifier.suppressed:
            print("  " + notifier.digest().replace("\n", "\n  "))
    low = sum(1 for _, a in results if a.confidence < 0.3)
    if low:
        print(f"  ! {low} returned low confidence -- treat those as leads, not answers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
