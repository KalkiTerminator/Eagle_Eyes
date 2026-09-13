#!/usr/bin/env python3
"""
Generate a synthetic iBot estate for local development.

Mirrors the real share layout so the analyzer can be pointed at a local folder
instead of a UNC path:

    <root>/Network_Sharing_Folder/data/<service line>/<bot number>/
        <year>/<month>/<date>/logs/user logs/
            logs/         *.log
            screenshot/   *.png
    <root>/code_folder/    <bot number>.txt

EVERY BYTE PRODUCED HERE IS FABRICATED. Names, policy numbers and account
references are generated from a fixed word list and refer to nobody. This
exists so that nobody is ever tempted to copy real client artifacts onto a
personal machine to test with -- see docs/SECURITY.md.

Pure stdlib: no pillow, no third-party deps.

Usage:
    python3 tools/make_fixtures.py --root ./sandbox [--seed 42] [--days 3]
"""

from __future__ import annotations

import argparse
import random
import shutil
import struct
import zlib
from datetime import datetime, timedelta
from pathlib import Path

# --------------------------------------------------------------------------
# Minimal PNG writer (stdlib only)
# --------------------------------------------------------------------------


def write_png(path: Path, width: int, height: int, draw_dialog: bool = True) -> None:
    """Write an RGB PNG. Crudely mimics a desktop with an error dialog on it."""
    bg = (58, 84, 122)          # desktop blue
    win = (240, 240, 240)       # application window
    dialog = (252, 252, 252)    # error dialog
    accent = (196, 43, 43)      # error banner

    rows = []
    dx0, dx1 = int(width * 0.30), int(width * 0.70)
    dy0, dy1 = int(height * 0.35), int(height * 0.62)

    for y in range(height):
        row = bytearray()
        for x in range(width):
            if 0.06 * width < x < 0.94 * width and 0.10 * height < y < 0.90 * height:
                px = win
            else:
                px = bg
            if draw_dialog and dx0 <= x <= dx1 and dy0 <= y <= dy1:
                px = accent if y < dy0 + max(6, height // 40) else dialog
            row += bytes(px)
        rows.append(bytes(row))

    raw = b"".join(b"\x00" + r for r in rows)  # filter byte 0 per scanline

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 6))
    png += chunk(b"IEND", b"")
    path.write_bytes(png)


# --------------------------------------------------------------------------
# Synthetic content
# --------------------------------------------------------------------------

SERVICE_LINES = ["INSURANCE_OPS", "CLAIMS_PROC", "FINANCE_AP"]

# Fabricated people. Any resemblance to a real person is accidental.
FAKE_NAMES = [
    "A. Marchetti", "R. Okonkwo", "L. Baptiste", "T. Halvorsen",
    "M. Sandoval", "K. Fairweather", "D. Achterberg", "S. Nakamura",
]

# Each template is one distinct root cause. `vision` marks the ones whose
# diagnosis genuinely needs the screenshot -- the escalation gate in
# docs/COST_MODEL.md section 6 should agree with this column.
TEMPLATES = [
    {
        "key": "selector",
        "exc": "iBot.Core.ElementNotFoundException",
        "msg": "Could not find UI element matching selector "
               "'<wnd app=\"polcore.exe\" cls=\"WindowsForms10\" idx=\"{idx}\" />' "
               "after {timeout}ms",
        "activity": "ClickPolicyTab",
        "vision": True,
    },
    {
        "key": "modal",
        "exc": "iBot.Core.UnexpectedWindowException",
        "msg": "Unexpected modal dialog blocked interaction: "
               "'Record locked by {name} (session {sid})'",
        "activity": "SavePolicyRecord",
        "vision": True,
    },
    {
        "key": "filenotfound",
        "exc": "System.IO.FileNotFoundException",
        "msg": "Could not find file "
               "'D:\\ibot\\input\\batch_{batch}\\remittance_{ref}.xlsx'",
        "activity": "ReadRemittanceFile",
        "vision": False,
    },
    {
        "key": "credential",
        "exc": "iBot.Security.CredentialExpiredException",
        "msg": "Credential 'SVC_POLCORE_BOT' expired at {ts}; "
               "authentication rejected for endpoint https://polcore.internal:{port}/auth",
        "activity": "AuthenticateToPolCore",
        "vision": False,
    },
    {
        "key": "timeout",
        "exc": "iBot.Core.ApplicationNotRespondingException",
        "msg": "Application 'polcore.exe' (pid {pid}) stopped responding "
               "for {timeout}ms while awaiting 'Policy {policy} saved'",
        "activity": "WaitForSaveConfirmation",
        "vision": True,
    },
    {
        "key": "sql",
        "exc": "System.Data.SqlClient.SqlException",
        "msg": "Timeout expired before completion of "
               "'usp_GetOpenClaims @ClaimRef={ref}' (conn {sid})",
        "activity": "FetchOpenClaims",
        "vision": False,
    },
]

STACK = [
    "   at iBot.Runtime.ActivityHost.Execute(ActivityContext ctx) in ActivityHost.cs:line {l1}",
    "   at iBot.Runtime.Sequence.RunNext(Int32 step) in Sequence.cs:line {l2}",
    "   at iBot.Workflows.{sl}.{act}.Run() in {act}.xaml:line {l3}",
    "   at iBot.Runtime.Scheduler.Dispatch(Job job) in Scheduler.cs:line {l4}",
]


def make_log(rng: random.Random, tpl: dict, bot: str, sl: str, when: datetime, run_id: str) -> str:
    """One iBot-shaped execution log ending in a failure.

    NOTE: this format is a placeholder. Replace it with a real (sanitized)
    sample before tuning the fingerprint normalization -- see
    docs/OPEN_QUESTIONS.md D1.
    """
    msg = tpl["msg"].format(
        idx=rng.randint(1, 60),
        timeout=rng.choice([15000, 30000, 45000, 60000]),
        name=rng.choice(FAKE_NAMES),
        sid=f"{rng.randrange(16**8):08x}",
        batch=rng.randint(1000, 9999),
        ref=f"{rng.randrange(16**12):012X}",
        ts=(when - timedelta(hours=rng.randint(1, 40))).isoformat(timespec="seconds"),
        port=rng.choice([443, 8443, 9443]),
        pid=rng.randint(1000, 65000),
        policy=f"POL-{rng.randint(100000, 999999)}",
    )
    stack = "\n".join(
        s.format(
            l1=rng.randint(100, 999), l2=rng.randint(100, 999),
            l3=rng.randint(10, 400), l4=rng.randint(100, 999),
            sl=sl.title().replace("_", ""), act=tpl["activity"],
        )
        for s in STACK
    )
    head = "\n".join(
        f"{(when - timedelta(seconds=n * 7)).isoformat(timespec='milliseconds')} "
        f"INFO  [{run_id}] {line}"
        for n, line in reversed(list(enumerate([
            "Queue item dequeued", "Application attached: polcore.exe",
            f"Processing record for {rng.choice(FAKE_NAMES)} "
            f"(policy POL-{rng.randint(100000, 999999)})",
            f"Navigating to {tpl['activity']}",
        ], start=1)))
    )
    return (
        f"=== iBot execution log ===\n"
        f"Bot        : {bot}\n"
        f"ServiceLine: {sl}\n"
        f"RunId      : {run_id}\n"
        f"Machine    : VM-{sl[:3]}-{rng.randint(10, 99)}\n"
        f"Started    : {(when - timedelta(seconds=40)).isoformat(timespec='milliseconds')}\n\n"
        f"{head}\n"
        f"{when.isoformat(timespec='milliseconds')} ERROR [{run_id}] "
        f"Activity '{tpl['activity']}' failed\n"
        f"{when.isoformat(timespec='milliseconds')} ERROR [{run_id}] "
        f"{tpl['exc']}: {msg}\n{stack}\n"
        f"{when.isoformat(timespec='milliseconds')} ERROR [{run_id}] "
        f"Screenshot captured\n"
        f"{when.isoformat(timespec='milliseconds')} INFO  [{run_id}] Run terminated\n"
    )


def make_code(bot: str, sl: str) -> str:
    """Stand-in for code pasted out of iBot into Notepad (no version metadata)."""
    return f"""' ---------------------------------------------------------------
' iBot process export  -  {bot}  ({sl})
' Pasted from the iBot designer. There is no version identifier in
' this file; the analyzer uses its mtime as a pseudo-version.
' See docs/ARCHITECTURE.md section 4.5.
' ---------------------------------------------------------------

Sequence Main
    Try
        AttachApplication "polcore.exe"
        AuthenticateToPolCore(credential := "SVC_POLCORE_BOT")

        For Each item In GetQueueItems()
            ClickPolicyTab(selector := "<wnd app='polcore.exe' idx='12' />")
            ReadRemittanceFile(path := "D:\\ibot\\input\\batch_" & item.Batch)
            FetchOpenClaims(claimRef := item.ClaimRef)
            SavePolicyRecord(item)
            WaitForSaveConfirmation(timeout := 30000)
        Next

    Catch ex As Exception
        LogError(ex)
        CaptureScreenshot()
        Throw
    End Try
End Sequence
"""


# --------------------------------------------------------------------------
# Estate generation
# --------------------------------------------------------------------------


def generate(root: Path, seed: int, days: int) -> dict:
    rng = random.Random(seed)
    share = root / "Network_Sharing_Folder"
    code_dir = root / "code_folder"
    if root.exists():
        shutil.rmtree(root)
    share.mkdir(parents=True)
    code_dir.mkdir(parents=True)

    # Bot numbers are globally unique here, one block per service line. If real
    # bot numbers are only unique WITHIN a service line, `<bot>.txt` is an
    # ambiguous key for the code folder and it must be keyed by
    # (service_line, bot_number) instead -- docs/OPEN_QUESTIONS.md D7.
    bots = [
        (sl, f"BOT{100 * i + n:03d}")
        for i, sl in enumerate(SERVICE_LINES)
        for n in range(1, 4)
    ]
    for sl, bot in bots:
        (code_dir / f"{bot}.txt").write_text(make_code(bot, sl), encoding="utf-8")

    stats = {"failures": 0, "screenshots": 0, "scenarios": {}}
    base = datetime.now().replace(hour=9, minute=0, second=0, microsecond=0)

    def emit(sl, bot, when, tpl, *, screenshot=True, dialog=True):
        d = (share / "data" / sl / bot / f"{when:%Y}" / f"{when:%m}" / f"{when:%d}"
             / "logs" / "user logs")
        (d / "logs").mkdir(parents=True, exist_ok=True)
        (d / "screenshot").mkdir(parents=True, exist_ok=True)
        run_id = f"{when:%Y%m%d}-{rng.randrange(16**6):06x}"
        (d / "logs" / f"{bot}_{when:%Y%m%d_%H%M%S}_{run_id}.log").write_text(
            make_log(rng, tpl, bot, sl, when, run_id), encoding="utf-8")
        stats["failures"] += 1
        if screenshot:
            write_png(d / "screenshot" / f"{bot}_{when:%Y%m%d_%H%M%S}_{run_id}.png",
                      1280, 720, draw_dialog=dialog)
            stats["screenshots"] += 1
        return run_id

    # A: the same root cause recurring across bots and days -- dedup should
    #    collapse all of these to one analysis.
    n = 0
    tpl = TEMPLATES[0]
    for day in range(days):
        for sl, bot in bots[:4]:
            for _ in range(rng.randint(1, 3)):
                when = base - timedelta(days=day, minutes=rng.randint(0, 400))
                emit(sl, bot, when, tpl)
                n += 1
    stats["scenarios"]["A_recurring_same_cause"] = n

    # B: incident spike -- one cause, many failures in minutes. #2..#N must all
    #    dedup and cost nothing.
    sl, bot = bots[4]
    spike = base - timedelta(days=1, hours=2)
    for i in range(200):
        emit(sl, bot, spike + timedelta(seconds=i * 3), TEMPLATES[4])
    stats["scenarios"]["B_incident_spike"] = 200

    # C: assorted distinct causes -- each should be analysed once.
    n = 0
    for day in range(days):
        for tpl in TEMPLATES[1:]:
            sl, bot = rng.choice(bots)
            emit(sl, bot, base - timedelta(days=day, minutes=rng.randint(0, 400)), tpl)
            n += 1
    stats["scenarios"]["C_distinct_causes"] = n

    # D: log with no screenshot -- must degrade to text-only, not fail.
    sl, bot = bots[5]
    emit(sl, bot, base - timedelta(hours=3), TEMPLATES[2], screenshot=False)
    stats["scenarios"]["D_missing_screenshot"] = 1

    # E: two failures 2s apart on one bot -- if pairing is timestamp-based the
    #    correlator must refuse to attach rather than guess (ARCHITECTURE 4.4).
    sl, bot = bots[6]
    amb = base - timedelta(hours=5)
    emit(sl, bot, amb, TEMPLATES[0])
    emit(sl, bot, amb + timedelta(seconds=2), TEMPLATES[3])
    stats["scenarios"]["E_ambiguous_pairing"] = 2

    # F: a bot with no code file at all -- analysis should proceed on the log
    #    alone with capped confidence.
    sl, bot = bots[7]
    emit(sl, bot, base - timedelta(hours=6), TEMPLATES[5])
    (code_dir / f"{bot}.txt").unlink()
    stats["scenarios"]["F_missing_code_file"] = 1

    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default="./sandbox", type=Path)
    ap.add_argument("--seed", default=42, type=int)
    ap.add_argument("--days", default=3, type=int)
    args = ap.parse_args()

    stats = generate(args.root, args.seed, args.days)
    print(f"Synthetic estate written to {args.root.resolve()}")
    print(f"  {stats['failures']} logs, {stats['screenshots']} screenshots")
    for name, count in stats["scenarios"].items():
        print(f"  {name:28s} {count:>4}")
    print("\nAll content is fabricated. Never replace it with real client data.")


if __name__ == "__main__":
    main()
