"""Let the user choose what gets analysed, and override what was guessed.

Three ways in, in order of preference on a given machine:

  1. GUI pickers (tkinter, bundled with Windows Python) -- pick a folder or a
     single log file the way you would in Explorer.
  2. A numbered text menu -- same choices, works over RDP with no display, and
     works here in CI.
  3. Command-line arguments -- for the scheduled, unattended run.

All three converge on the same review step: a table of what was found, what it
will cost, and which inputs each failure will use. Nothing is sent to a model
until the user says go.

The review is where "power to the user" actually lives. Automatic pairing and
code resolution are proposals, not decisions: every one can be overridden, and
the reasoning behind each is shown rather than hidden.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .discovery import FailureCandidate

# Cost per path, from docs/COST_MODEL.md section 3.
COST_TRIAGE = 0.00425
COST_TEXT = 0.0384
COST_VISION = 0.040752


# ---------------------------------------------------------------------------
# Pickers
# ---------------------------------------------------------------------------

def gui_available() -> bool:
    try:
        import tkinter  # noqa: F401
        return True
    except Exception:
        return False


def pick_folder(title: str = "Select a folder to analyse",
                initial: Path | None = None) -> Path | None:
    """Explorer-style folder picker; None if the user cancels."""
    if not gui_available():
        return _prompt_path(title, want_dir=True, initial=initial)
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        chosen = filedialog.askdirectory(title=title,
                                         initialdir=str(initial) if initial else None)
    finally:
        root.destroy()
    return Path(chosen) if chosen else None


def pick_file(title: str = "Select a log file",
              initial: Path | None = None) -> Path | None:
    if not gui_available():
        return _prompt_path(title, want_dir=False, initial=initial)
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        chosen = filedialog.askopenfilename(
            title=title,
            initialdir=str(initial) if initial else None,
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
        )
    finally:
        root.destroy()
    return Path(chosen) if chosen else None


def _prompt_path(title: str, want_dir: bool, initial: Path | None) -> Path | None:
    """Text fallback: browse the tree one level at a time. Works headless."""
    here = Path(initial) if initial else Path.cwd()
    while True:
        print(f"\n{title}")
        print(f"  in: {here}")
        entries = sorted([p for p in here.iterdir() if p.is_dir()]) + \
                  ([] if want_dir else sorted(p for p in here.iterdir()
                                              if p.is_file() and p.suffix in (".log", ".txt")))
        for i, p in enumerate(entries[:40], 1):
            print(f"   {i:>3}. {'[dir] ' if p.is_dir() else '      '}{p.name}")
        if len(entries) > 40:
            print(f"        ... and {len(entries) - 40} more")
        hint = "number to open, 'u' up, '.' use this folder, 'q' cancel" if want_dir \
            else "number to open/select, 'u' up, 'q' cancel"
        raw = input(f"  [{hint}]: ").strip().lower()
        if raw in ("q", ""):
            return None
        if raw == "u":
            here = here.parent
            continue
        if raw == "." and want_dir:
            return here
        if raw.isdigit() and 1 <= int(raw) <= len(entries):
            chosen = entries[int(raw) - 1]
            if chosen.is_file():
                return chosen
            here = chosen
            continue
        print("  ? not understood")


# ---------------------------------------------------------------------------
# Review
# ---------------------------------------------------------------------------

def estimate_cost(cands: list[FailureCandidate]) -> tuple[float, dict]:
    """Upper bound: assumes nothing dedups. Real cost is usually far lower."""
    sel = [c for c in cands if c.selected]
    vision = sum(1 for c in sel if c.screenshot_path and c.send_screenshot)
    text = len(sel) - vision
    total = len(sel) * COST_TRIAGE + vision * COST_VISION + text * COST_TEXT
    return total, {"selected": len(sel), "vision": vision, "text": text}


def render_table(cands: list[FailureCandidate], limit: int = 30) -> str:
    rows = [
        f"{'#':>3}  {'':1} {'bot':<8} {'time':<8} {'exception':<42} {'inputs':<14} pairing",
        "-" * 108,
    ]
    for i, c in enumerate(cands[:limit], 1):
        mark = "x" if c.selected else " "
        when = c.occurred_at.strftime("%H:%M:%S") if c.occurred_at else "--"
        exc = (c.exception_type or "(unparsed)").split(".")[-1][:42]
        pairing = c.pairing_method if c.pairing_method != "none" else f"none - {c.pairing_note}"
        rows.append(f"{i:>3}  [{mark}] {c.location.bot_number:<8} {when:<8} "
                    f"{exc:<42} {c.inputs:<14} {pairing}")
    if len(cands) > limit:
        rows.append(f"     ... and {len(cands) - limit} more (all selected by default)")
    return "\n".join(rows)


def summarize(cands: list[FailureCandidate]) -> str:
    total, parts = estimate_cost(cands)
    stale = sum(1 for c in cands if c.selected and c.code_possibly_stale)
    nocode = sum(1 for c in cands if c.selected and not c.code_path)
    unpaired = sum(1 for c in cands if c.selected and c.screenshot_path is None)

    lines = [
        f"  {parts['selected']} of {len(cands)} failures selected",
        f"  {parts['vision']} with a screenshot, {parts['text']} text-only",
        f"  estimated cost if NOTHING dedups: ${total:,.2f}   "
        f"(real cost is usually far lower -- most failures repeat)",
    ]
    if unpaired:
        lines.append(f"  ! {unpaired} have no screenshot attached (see the pairing column)")
    if stale:
        lines.append(f"  ! {stale} use code edited AFTER the failure -- marked code* and "
                     f"analysed with reduced confidence")
    if nocode:
        lines.append(f"  ! {nocode} have no code file at all -- log-only analysis")
    return "\n".join(lines)


HELP = """
  Commands
    <enter>            run the selected failures
    a                  select all          n      select none
    3                  toggle row 3        3-9    toggle a range
    v 3                toggle sending the screenshot for row 3
    s 3                choose a different screenshot for row 3
    c 3                choose a different code file for row 3
    f 3                re-analyse row 3 even if it was analysed before
    d 3                show everything known about row 3
    ?                  this help          q      cancel, send nothing
"""


def review(cands: list[FailureCandidate], code_root: Path,
           interactive: bool = True) -> list[FailureCandidate]:
    """Show what was found and let the user change it. Returns what to run."""
    if not cands:
        print("\nNothing found there.")
        return []

    while True:
        print("\n" + render_table(cands))
        print()
        print(summarize(cands))
        if not interactive:
            return [c for c in cands if c.selected]

        raw = input("\n  [enter=run, ?=help, q=cancel] > ").strip()
        if raw == "":
            return [c for c in cands if c.selected]
        if raw.lower() == "q":
            print("  Cancelled. Nothing was sent.")
            return []
        if raw == "?":
            print(HELP)
            continue
        if raw.lower() == "a":
            for c in cands:
                c.selected = True
            continue
        if raw.lower() == "n":
            for c in cands:
                c.selected = False
            continue

        parts = raw.split()
        verb, arg = (parts[0].lower(), parts[1] if len(parts) > 1 else "")

        if verb.isdigit() or "-" in verb:
            for idx in _parse_range(verb, len(cands)):
                cands[idx].selected = not cands[idx].selected
            continue

        if not arg.isdigit() or not (1 <= int(arg) <= len(cands)):
            print("  ? give a row number, e.g. 'v 3'")
            continue
        c = cands[int(arg) - 1]

        if verb == "v":
            if c.screenshot_path is None:
                print("  no screenshot attached to that row")
            else:
                c.send_screenshot = not c.send_screenshot
                print(f"  screenshot {'will' if c.send_screenshot else 'will NOT'} be sent")
        elif verb == "s":
            chosen = _choose(c.alternatives, "Screenshots in that folder")
            if chosen:
                c.screenshot_path, c.pairing_method = chosen, "manual"
                c.pairing_note, c.send_screenshot = "chosen by the user", True
        elif verb == "c":
            chosen = pick_file("Select the code file for this bot", initial=code_root)
            if chosen:
                c.code_path = chosen
                c.code_possibly_stale = False
                print(f"  code set to {chosen.name} (staleness check waived)")
        elif verb == "f":
            c.force_reanalyze = not c.force_reanalyze
            print(f"  re-analysis {'forced' if c.force_reanalyze else 'not forced'}")
        elif verb == "d":
            print(_detail(c))
        else:
            print("  ? unknown command, '?' for help")


def _parse_range(token: str, n: int) -> list[int]:
    if "-" in token:
        a, _, b = token.partition("-")
        if a.isdigit() and b.isdigit():
            return [i - 1 for i in range(int(a), int(b) + 1) if 1 <= i <= n]
        return []
    return [int(token) - 1] if token.isdigit() and 1 <= int(token) <= n else []


def _choose(options: list[Path], title: str) -> Path | None:
    if not options:
        print("  nothing to choose from")
        return None
    print(f"\n  {title}")
    for i, p in enumerate(options, 1):
        print(f"   {i:>3}. {p.name}")
    raw = input("  [number, or enter to keep current]: ").strip()
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    return None


def _detail(c: FailureCandidate) -> str:
    return "\n".join([
        "",
        f"  log        : {c.log_path}",
        f"  location   : {c.location.label}",
        f"  occurred   : {c.occurred_at}",
        f"  exception  : {c.exception_type}",
        f"  message    : {c.message[:200]}",
        f"  screenshot : {c.screenshot_path or '(none)'}",
        f"  pairing    : {c.pairing_method} - {c.pairing_note}",
        f"  code       : {c.code_path or '(none)'}",
        f"  code mtime : {c.code_mtime}"
        + ("   [EDITED AFTER THE FAILURE - may not be what ran]"
           if c.code_possibly_stale else ""),
        f"  will send  : {c.inputs}",
        "",
    ])
