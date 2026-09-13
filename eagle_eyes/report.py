"""HTML reports — how the diagnosis reaches someone who did not run the tool.

A result that exists only in one person's terminal has not been delivered. The
premise is that developers get value without changing how they work, so reports
are written to a folder colleagues can already open.

Three rules the markup follows, from docs/SECURITY.md:

  * The screenshot is NEVER embedded. The report links to the file where it
    already sits, so the estate's existing ACLs decide who can open it. An
    embedded image would copy client pixels into a file on a shared folder and
    quietly undo Mode 0.
  * Every value coming from a log, a model or a filename is escaped. Log lines
    are attacker-influenced text; a report that renders them raw is a stored
    XSS waiting for someone to open it in a browser.
  * Low confidence and stale code are shown prominently, not in a footnote. A
    confident-looking report over a 0.2-confidence answer is the failure mode
    this whole system is trying to avoid.
"""

from __future__ import annotations

import html
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

CSS = """
:root { --fg:#1a1a1a; --muted:#666; --line:#e0e0e0; --bg:#fff;
        --ok:#1a7f37; --warn:#9a6700; --bad:#b42318; --panel:#f6f8fa; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e6e6e6; --muted:#9a9a9a; --line:#333; --bg:#141414;
          --ok:#3fb950; --warn:#d29922; --bad:#f85149; --panel:#1c1c1c; }
}
* { box-sizing:border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
       font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width:880px; margin:0 auto; }
h1 { font-size:19px; margin:0 0 4px; }
h2 { font-size:14px; text-transform:uppercase; letter-spacing:.06em;
     color:var(--muted); margin:26px 0 8px; font-weight:600; }
.sub { color:var(--muted); font-size:13px; margin-bottom:18px; }
.panel { background:var(--panel); border:1px solid var(--line);
         border-radius:6px; padding:14px 16px; }
pre { white-space:pre-wrap; word-break:break-word; margin:0;
      font:12.5px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace; }
table { border-collapse:collapse; width:100%; font-size:13px; }
td,th { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line);
        vertical-align:top; }
th { color:var(--muted); font-weight:600; width:190px; }
.bar { height:6px; background:var(--line); border-radius:3px; overflow:hidden;
       max-width:220px; margin-top:5px; }
.bar > i { display:block; height:100%; }
.ok > i{background:var(--ok)} .warn > i{background:var(--warn)} .bad > i{background:var(--bad)}
.flag { border-left:3px solid var(--warn); background:var(--panel);
        padding:10px 14px; margin:12px 0; border-radius:0 4px 4px 0; }
.flag.bad { border-left-color:var(--bad); }
a { color:inherit; }
.foot { color:var(--muted); font-size:12px; margin-top:30px;
        border-top:1px solid var(--line); padding-top:12px; }
@media (max-width:520px){ body{padding:14px} th{width:auto;display:block;border:0;padding-bottom:0}
  td{display:block;padding-top:2px} }
"""


def _e(value: object) -> str:
    """Escape everything. Log text and model output are both untrusted."""
    return html.escape(str(value if value is not None else ""), quote=True)


def _file_url(path: str | os.PathLike) -> str:
    p = str(path)
    if p.startswith("\\\\"):                         # UNC -> file://server/share
        return "file:" + p.replace("\\", "/")
    return Path(p).as_uri() if os.path.isabs(p) else _e(p)


def _confidence_block(conf: float) -> str:
    cls = "ok" if conf >= 0.7 else "warn" if conf >= 0.3 else "bad"
    label = ("clear" if conf >= 0.7 else
             "likely, with alternatives" if conf >= 0.3 else
             "not supported by the evidence")
    return (f'{conf:.2f} &mdash; {label}'
            f'<div class="bar {cls}"><i style="width:{max(conf, 0.02) * 100:.0f}%"></i></div>')


@dataclass
class ReportInput:
    """Everything a report needs, already sanitized."""
    bot_label: str
    occurred_at: str
    exception_type: str
    root_cause: str
    suggested_fix: str
    confidence: float
    path: str
    category: str = "novel"
    notes: str = ""
    inputs_used: tuple[str, ...] = ()
    log_path: str = ""
    screenshot_path: str = ""
    pairing_method: str = "none"
    code_path: str = ""
    code_possibly_stale: bool = False
    model_id: str = ""
    cost_usd: float | None = None
    log_excerpt: str = ""


def render(r: ReportInput) -> str:
    flags = []
    if r.confidence < 0.3:
        flags.append(
            '<div class="flag bad"><b>Low confidence.</b> The evidence does not clearly '
            'support this diagnosis. Treat it as a lead to check, not an answer.</div>')
    if r.code_possibly_stale:
        flags.append(
            '<div class="flag"><b>The code file was edited after this failure.</b> It may '
            'not be what the bot was running, so line-level claims cannot be relied on.</div>')
    if r.screenshot_path and "screenshot" not in r.inputs_used:
        flags.append(
            '<div class="flag">A screenshot exists but was <b>not sent to the model</b>. '
            'Open it below if the diagnosis looks incomplete.</div>')
    if not r.code_path:
        flags.append(
            '<div class="flag">No code file was found for this bot, so this is a '
            '<b>log-only</b> diagnosis.</div>')
    if r.pairing_method == "none" and r.screenshot_path:
        flags.append(
            '<div class="flag">The screenshot could not be matched to this failure with '
            'confidence, so none was attached rather than risk the wrong one.</div>')

    rows = [
        ("Bot", _e(r.bot_label)),
        ("Occurred", _e(r.occurred_at)),
        ("Exception", f"<code>{_e(r.exception_type)}</code>"),
        ("Confidence", _confidence_block(r.confidence)),
        ("Inputs used", _e(", ".join(r.inputs_used) or "log only")),
        ("Analysis path", _e(r.path)),
    ]
    if r.log_path:
        rows.append(("Log", f'<a href="{_file_url(r.log_path)}">{_e(r.log_path)}</a>'))
    if r.screenshot_path:
        rows.append(("Screenshot",
                     f'<a href="{_file_url(r.screenshot_path)}">{_e(r.screenshot_path)}</a>'
                     f'<br><span style="color:var(--muted)">paired by '
                     f'{_e(r.pairing_method)} &middot; opens with your existing access; '
                     f'not copied into this report</span>'))
    if r.code_path:
        rows.append(("Code", f'<a href="{_file_url(r.code_path)}">{_e(r.code_path)}</a>'))
    if r.model_id:
        cost = (f" &middot; ${r.cost_usd:.4f}" if r.cost_usd is not None
                else " &middot; cost unknown")
        rows.append(("Model", _e(r.model_id) + cost))

    table = "\n".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
    notes = (f'<h2>Notes</h2><div class="panel"><pre>{_e(r.notes)}</pre></div>'
             if r.notes.strip() else "")
    excerpt = (f'<h2>Log excerpt</h2><div class="panel"><pre>{_e(r.log_excerpt)}</pre></div>'
               if r.log_excerpt.strip() else "")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(r.bot_label)} &mdash; {_e(r.exception_type.split('.')[-1])}</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>{_e(r.exception_type.split('.')[-1])}</h1>
<div class="sub">{_e(r.bot_label)} &middot; {_e(r.occurred_at)}</div>
{''.join(flags)}
<h2>Root cause</h2><div class="panel"><pre>{_e(r.root_cause)}</pre></div>
<h2>Suggested fix</h2><div class="panel"><pre>{_e(r.suggested_fix)}</pre></div>
{notes}
<h2>Evidence</h2><table>{table}</table>
{excerpt}
<div class="foot">Generated by Eagle Eyes on {_e(datetime.now().strftime('%Y-%m-%d %H:%M'))}.
This is an automated diagnosis and can be wrong &mdash; the confidence above is the
system's own estimate. Please mark it correct, partial or wrong; that feedback is
what stops a bad analysis being served to the next person.</div>
</div></body></html>"""


def write(r: ReportInput, out_dir: Path, name: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)[:120]
    path = out_dir / f"{safe}.html"
    path.write_text(render(r), encoding="utf-8")
    return path


def write_index(reports: Iterable[tuple[ReportInput, Path]], out_dir: Path) -> Path:
    items = sorted(reports, key=lambda t: t[0].occurred_at, reverse=True)
    rows = "\n".join(
        f'<tr><td>{_e(r.occurred_at[:16])}</td><td>{_e(r.bot_label)}</td>'
        f'<td><code>{_e(r.exception_type.split(".")[-1])}</code></td>'
        f'<td>{r.confidence:.2f}</td>'
        f'<td><a href="{_e(p.name)}">open</a></td></tr>'
        for r, p in items)
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Eagle Eyes &mdash; recent failures</title><style>{CSS}</style></head>
<body><div class="wrap"><h1>Recent failures</h1>
<div class="sub">{len(items)} analysed &middot; {_e(datetime.now().strftime('%Y-%m-%d %H:%M'))}</div>
<table><tr><th>When</th><th>Bot</th><th>Exception</th><th>Conf.</th><th></th></tr>
{rows}</table></div></body></html>"""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "index.html"
    path.write_text(body, encoding="utf-8")
    return path
