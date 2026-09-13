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
from pathlib import Path

from .analysis import Engine
from .cache import SharedCache
from .discovery import discover, read_text
from .model_gateway import BudgetGuard, create_backend, models_for
from .runtime import describe_host, resolve_paths
from .selection import estimate_cost, pick_file, pick_folder, review


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="eagle_eyes", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pick-folder", action="store_true", help="choose a folder in a dialog")
    src.add_argument("--pick-file", action="store_true", help="choose one log file in a dialog")
    src.add_argument("--target", type=Path, help="analyse this file or folder directly")

    ap.add_argument("--share-root", type=Path, required=True,
                    help="root containing data/<service line>/...")
    ap.add_argument("--code-root", type=Path, required=True, help="folder of bot code files")
    ap.add_argument("--yes", action="store_true",
                    help="skip the review and run everything found (for the scheduler)")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be analysed, then stop")
    ap.add_argument("--backend", default="mock", choices=["mock", "bedrock", "byok"],
                    help="mock costs nothing and needs no credentials (default)")
    ap.add_argument("--region", default="", help="AWS region, for the bedrock backend")
    ap.add_argument("--screenshot-mode", type=int, default=0, choices=[0, 1, 2, 3],
                    help="0 = never send a screenshot to a model (default)")
    ap.add_argument("--shared-cache", type=Path,
                    help="directory every install can reach, for shared dedup")
    ap.add_argument("--budget", type=float, default=2.00,
                    help="stop this run once it would exceed this many dollars")
    args = ap.parse_args(argv)

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

    if not cands:
        print("  No failure logs found there.")
        print("  (Logs are expected under .../logs/user logs/logs/ inside the share root.)")
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
        backend = create_backend(
            {"backend": args.backend, "region": args.region},
            environment="local")
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
    low = sum(1 for _, a in results if a.confidence < 0.3)
    if low:
        print(f"  ! {low} returned low confidence -- treat those as leads, not answers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
