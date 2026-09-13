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
# Shapes follow fixtures/samples/: C#/.NET driving Selenium.
TEMPLATES = [
    {
        "key": "intercepted",
        "exc": "OpenQA.Selenium.ElementClickInterceptedException",
        "msg": ("element click intercepted: Element <a data-tab=\"policy\" href=\"#policy\">...</a> "
                "is not clickable at point ({x}, {y}). Other element would receive the click: "
                "<div class=\"session-warning-banner\" role=\"alert\">...</div>"),
        "activity": "PostSingleRemittance",
        "vision": True,
    },
    {
        "key": "stale",
        "exc": "OpenQA.Selenium.StaleElementReferenceException",
        "msg": "stale element reference: element is not attached to the page document",
        "activity": "FillClaimHeader",
        "vision": False,
    },
    {
        "key": "nosuchelement",
        "exc": "OpenQA.Selenium.NoSuchElementException",
        "msg": ("no such element: Unable to locate element: "
                "{{\"method\":\"css selector\",\"selector\":\"li.attachment-row\"}}"),
        "activity": "AttachDocuments",
        "vision": True,
    },
    {
        "key": "timeout",
        "exc": "OpenQA.Selenium.WebDriverTimeoutException",
        "msg": "Timed out after {timeout} seconds waiting for element to be clickable",
        "activity": "OpenClaimForm",
        "vision": True,
    },
    {
        "key": "neterr",
        "exc": "OpenQA.Selenium.WebDriverException",
        "msg": "unknown error: net::ERR_CONNECTION_TIMED_OUT loading https://polcore.internal/finance/remittance",
        "activity": "Navigate",
        "vision": False,
    },
    {
        "key": "filenotfound",
        "exc": "System.IO.FileNotFoundException",
        "msg": "Could not find file 'D:\\ibot\\input\\batch_{batch}\\remittance_{ref}.xlsx'",
        "activity": "ReadRange",
        "vision": False,
    },
]

STACK = [
    "   at OpenQA.Selenium.WebDriver.UnpackAndThrowOnError(Response errorResponse, String commandToExecute)",
    "   at OpenQA.Selenium.WebDriver.Execute(String driverCommandToExecute, Dictionary`2 parameters)",
    "   at OpenQA.Selenium.WebElement.Click()",
    "   at iBot.Processes.{ns}.{proc}.{act}(String policyRef) in C:\\ibot\\processes\\{ns}\\{proc}.cs:line {l1}",
    "   at iBot.Runtime.Engine.RunProcess(ProcessDefinition def, QueueItem item) in C:\\build\\ibot\\src\\Runtime\\Engine.cs:line {l2}",
]

CHROME_BUILDS = ["128.0.6613.120", "128.0.6613.138", "129.0.6668.58", "129.0.6668.101"]


def make_log(rng: random.Random, tpl: dict, bot: str, sl: str, when: datetime,
             run_id: str, shot_name: str | None) -> str:
    """One iBot-shaped C#/Selenium execution log ending in a failure.

    Format follows fixtures/samples/. Still a placeholder: replace it with a
    real sanitized sample before tuning normalization (docs/OPEN_QUESTIONS.md D1).
    """
    proc = "AP_RemittancePosting" if sl == "FINANCE_AP" else "CLM_ClaimIntake"
    ns = "Finance" if sl == "FINANCE_AP" else "Claims"
    chrome = rng.choice(CHROME_BUILDS)          # varies: the dedup trap, normalized away

    msg = tpl["msg"].format(
        x=rng.randint(100, 1400), y=rng.randint(100, 900),
        timeout=rng.choice([10, 20, 30]),
        batch=rng.randint(1000, 9999),
        ref=f"{rng.randrange(16**12):012X}",
    )
    stack = "\n".join(
        f.format(ns=ns, proc=proc, act=tpl["activity"],
                 l1=rng.randint(40, 140), l2=rng.randint(500, 700))
        for f in STACK
    )
    ts = lambda d: (when + timedelta(seconds=d)).strftime("%d-%m-%Y %H:%M:%S.%f")[:-3]
    head = "\n".join([
        f"{ts(-38)} [INFO ] Runtime initialised (v7.4.2, .NET 4.8.9256.0)",
        f"{ts(-37)} [INFO ] Queue item {rng.randint(8800000, 8899999)} dequeued",
        f"{ts(-35)} [INFO ] Starting ChromeDriver {chrome} on port {rng.randint(49000, 52000)}",
        f"{ts(-32)} [INFO ] Chrome session {rng.randrange(16**24):024x} started",
        f"{ts(-30)} [INFO ] Authenticated as SVC_{sl[:3]}_BOT",
        f"{ts(-12)} [INFO ] --- item {rng.randint(1, 300)}/318",
    ])
    shot_line = ""
    if shot_name:
        p = (f"D:\\ibot\\data\\{sl}\\{bot}\\{when:%Y}\\{when:%m}\\{when:%d}"
             f"\\logs\\user logs\\screenshot\\{shot_name}")
        shot_line = f"{ts(1)} [INFO ] Screenshot captured: {p}\n"

    return (
        "=========================================================================\n"
        " iBot Runtime 7.4.2  |  Execution Log\n"
        "=========================================================================\n"
        f"Process      : {proc}\n"
        f"BotNumber    : {bot}\n"
        f"ServiceLine  : {sl}\n"
        f"Machine      : VM-{sl[:3]}-{rng.randint(10, 99)}\n"
        f"RunId        : {run_id}\n"
        f"Started      : {ts(-40)}\n"
        "-------------------------------------------------------------------------\n"
        f"{head}\n"
        f"{ts(0)} [ERROR] Activity '{tpl['activity']}' failed\n"
        f"{ts(0)} [ERROR] {tpl['exc']}: {msg}\n"
        f"  (Session info: chrome={chrome})\n"
        f"{stack}\n"
        f"{shot_line}"
        f"{ts(2)} [INFO ] Run terminated with status FAILED\n"
    )


def make_code(bot: str, sl: str) -> str:
    """Stand-in for code pasted out of iBot into Notepad (no version metadata)."""
    proc = "AP_RemittancePosting" if sl == "FINANCE_AP" else "CLM_ClaimIntake"
    ns = "Finance" if sl == "FINANCE_AP" else "Claims"
    return f"""// -------------------------------------------------------------------
// Pasted out of the iBot designer -> Notepad -> saved as .txt
// Process : {proc}   Bot: {bot}   Line: {sl}
// No version stamp is included in the copy output; the analyzer uses
// this file's mtime as a pseudo-version (docs/ARCHITECTURE.md 4.5).
// -------------------------------------------------------------------

using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;
using iBot.Runtime;

namespace iBot.Processes.{ns}
{{
    public class {proc} : ProcessBase
    {{
        private IWebDriver driver;
        private WebDriverWait wait;

        public override void Execute(QueueItem item)
        {{
            driver = new ChromeDriver(@"C:\\ibot\\drivers");
            wait = new WebDriverWait(driver, TimeSpan.FromSeconds(30));
            driver.Navigate().GoToUrl("https://polcore.internal/finance/remittance");

            foreach (var row in LoadRows(item))
            {{
                wait.Until(ExpectedConditions.ElementToBeClickable(
                    By.XPath("//div[@id='policyTabs']//a[@data-tab='policy']"))).Click();
                driver.FindElement(By.Id("txtPolicyRef")).SendKeys(row.PolicyRef);
                driver.FindElement(By.Id("btnPost")).Click();
                wait.Until(ExpectedConditions.ElementIsVisible(
                    By.XPath("//div[contains(@class,'toast-success')]")));
            }}
        }}

        public override void OnError(Exception ex, QueueItem item)
        {{
            Log.Error(ex.ToString());
            Screenshot.Capture(driver);
            throw;
        }}
    }}
}}
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
        # Screenshot filenames are date-time only, as confirmed for the real estate.
        shot_name = f"{when + timedelta(seconds=1):%Y-%m-%d_%H-%M-%S}.png" if screenshot else None
        (d / "logs" / f"{bot}_{when:%Y%m%d_%H%M%S}_{run_id}.log").write_bytes(
            make_log(rng, tpl, bot, sl, when, run_id, shot_name)
            .replace("\n", "\r\n").encode("utf-8"))          # CRLF, like the real thing
        stats["failures"] += 1
        if shot_name:
            write_png(d / "screenshot" / shot_name, 1280, 720, draw_dialog=dialog)
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
