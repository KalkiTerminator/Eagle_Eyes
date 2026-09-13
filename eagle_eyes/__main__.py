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

from .discovery import discover
from .selection import gui_available, pick_file, pick_folder, review, estimate_cost


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

    print(f"\n{len(chosen)} selected. The analysis engine is not wired up yet;")
    print("this run stops here rather than pretending to have diagnosed anything.")
    for c in chosen[:5]:
        print(f"  - {c.location.label}  {c.exception_type.split('.')[-1]}  [{c.inputs}]")
    if len(chosen) > 5:
        print(f"  ... and {len(chosen) - 5} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
