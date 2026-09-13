"""`--doctor`: tell someone whether this machine can run the product, and what to fix.

The first question anyone asks of a new tool is "will this work here". Answering
it with a stack trace halfway through a run is a bad answer. This checks the
whole chain in a second, says which link is weak, and distinguishes what blocks
a run from what merely limits it.
"""

from __future__ import annotations

import os
import platform
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .runtime import (config_search_path, data_dir, gui_possible, is_frozen,
                      is_portable, resolve_paths)

OK, WARN, BAD = "ok", "warn", "bad"
MARK = {OK: "  ok ", WARN: "  !  ", BAD: " FAIL"}
MIN_PYTHON = (3, 10)


def _check(name: str, state: str, detail: str, fix: str = "") -> dict:
    return {"name": name, "state": state, "detail": detail, "fix": fix}


def run_checks(share_root: Path | None = None, code_root: Path | None = None) -> list[dict]:
    out: list[dict] = []

    v = sys.version_info
    out.append(_check(
        "Python", OK if v[:2] >= MIN_PYTHON else BAD,
        f"{platform.python_version()} ({sys.executable})",
        f"Install Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer."
        if v[:2] < MIN_PYTHON else ""))

    out.append(_check("Platform", OK,
                      f"{platform.system()} {platform.release()}"
                      + ("  (frozen build)" if is_frozen() else "")
                      + ("  (portable mode)" if is_portable() else "")))

    # Writable data directory -- everything persists here.
    try:
        paths = resolve_paths().ensure()
        probe = paths.data / ".doctor"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        out.append(_check("Data directory", OK, str(paths.data)))
    except OSError as exc:
        out.append(_check("Data directory", BAD, f"{data_dir()} -- {exc}",
                          "Set EAGLE_EYES_DATA_DIR to somewhere writable, or drop a "
                          "portable.txt beside the application to keep data alongside it."))

    try:
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t(a)")
        con.close()
        out.append(_check("SQLite", OK, f"{sqlite3.sqlite_version} (bundled with Python)"))
    except Exception as exc:
        out.append(_check("SQLite", BAD, str(exc), "Reinstall Python."))

    # tkinter only affects the pickers; the text browser works without it.
    if gui_possible():
        out.append(_check("Folder/file pickers", OK, "available"))
    else:
        try:
            import tkinter  # noqa: F401
            why = "tkinter present but no display is attached"
        except Exception:
            why = "tkinter not installed"
        out.append(_check("Folder/file pickers", WARN, why,
                          "Not a blocker -- the same choices appear as a numbered "
                          "text browser. On Linux install python3-tk for dialogs."))

    try:
        import anthropic  # noqa: F401
        out.append(_check("Model SDK", OK, f"anthropic {anthropic.__version__}"))
    except ImportError:
        out.append(_check("Model SDK", WARN, "anthropic not installed",
                          "Only needed for real analysis: pip install 'anthropic[bedrock]'. "
                          "The mock backend runs the whole pipeline without it."))

    creds = []
    if os.environ.get("ANTHROPIC_API_KEY"):
        creds.append("ANTHROPIC_API_KEY")
    if os.environ.get("AWS_PROFILE") or os.environ.get("AWS_ACCESS_KEY_ID"):
        creds.append("AWS credentials")
    out.append(_check("Credentials", OK if creds else WARN,
                      ", ".join(creds) if creds else "none found in the environment",
                      "" if creds else
                      "Only needed for real analysis. --backend mock needs nothing."))

    found = next((p for p in config_search_path() if p.is_file()), None)
    out.append(_check("Config file", OK if found else WARN,
                      str(found) if found else "none found (command-line flags only)",
                      "" if found else
                      "Optional today; every setting has a flag."))

    for label, root in (("Log share", share_root), ("Code folder", code_root)):
        if root is None:
            continue
        p = Path(root)
        if not p.exists():
            out.append(_check(label, BAD, f"{p} does not exist",
                              "Check the path, and that you can reach the share."))
        elif not os.access(p, os.R_OK):
            out.append(_check(label, BAD, f"{p} is not readable",
                              "The account running this needs read access."))
        else:
            n = sum(1 for _ in p.rglob("*.log")) if label == "Log share" else \
                sum(1 for _ in p.glob("*"))
            out.append(_check(label, OK if n else WARN, f"{p}  ({n} files)",
                              "" if n else "Readable but empty -- is this the right folder?"))
    return out


def report(checks: list[dict]) -> int:
    print(f"Eagle Eyes {__version__} -- environment check\n")
    for c in checks:
        print(f"{MARK[c['state']]} {c['name']:<22} {c['detail']}")
        if c["fix"]:
            for line in _wrap(c["fix"]):
                print(f"       {line}")
    bad = [c for c in checks if c["state"] == BAD]
    warn = [c for c in checks if c["state"] == WARN]
    print()
    if bad:
        print(f"{len(bad)} problem(s) will stop a run: "
              + ", ".join(c["name"] for c in bad))
        return 1
    if warn:
        print(f"Ready to run. {len(warn)} thing(s) limit what it can do, "
              f"but nothing blocks a mock run.")
    else:
        print("Ready to run.")
    print("\nTry it against synthetic data, which needs no credentials and costs nothing:")
    print("  python3 tools/make_fixtures.py --root ./sandbox")
    print("  python3 -m eagle_eyes --target ./sandbox/Network_Sharing_Folder "
          "\\\n      --share-root ./sandbox/Network_Sharing_Folder "
          "--code-root ./sandbox/code_folder --dry-run")
    return 0


def _wrap(text: str, width: int = 72) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines
