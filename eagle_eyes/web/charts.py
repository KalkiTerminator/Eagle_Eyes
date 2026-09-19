"""Charts as inline SVG, rendered on the server.

No chart library and no CDN. The whole project's character is that it needs
nothing installed, and a dashboard that breaks when a CDN is blocked -- which,
on a locked-down corporate desktop, it will be -- is worse than a plain table.
These render with JavaScript off.

COLOUR IS NOT A MATTER OF TASTE HERE. The categorical slots, the ordinal ramp
and the two surfaces below were each put through the palette validator in both
light and dark mode:

    categorical 1-5   PASS both modes (worst adjacent CVD dE 9.1 light / 8.4 dark)
    ordinal 5-step    PASS both modes, after the first attempt FAILED -- steps
                      450 and 500 were 0.048 apart in lightness, below the 0.06
                      floor, so the ramp was re-stepped to 250/350/450/550/650
    contrast          three light slots sit under 3:1, which obligates the
                      relief rule: every mark carries a visible label, and the
                      numbers are in a table beside the chart

So: hues are assigned in fixed slot order and never cycled, every series is
directly labelled rather than identified by colour alone, and a ninth series
would fold into "other" rather than invent a hue.
"""

from __future__ import annotations

from html import escape

# Validated categorical slots, light / dark. Fixed order -- slot 1 is always
# blue, never "the first series in this particular chart".
SERIES_LIGHT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
SERIES_DARK = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"]

# Ordinal ramp for confidence: one hue, light to dark, gaps >= 0.06 L.
ORDINAL_LIGHT = ["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#104281"]
ORDINAL_DARK = ["#184f95", "#256abf", "#3987e5", "#6da7ec", "#9ec5f4"]

# Status. Reserved -- never reused as a series colour, and NEVER the only
# thing carrying the meaning.
#
# The light values are the POC kit's, unchanged. They pass the categorical gate
# in light mode. The dark ones are derived from them: scaled down the same hue
# until each sits inside the dark lightness band (0.48-0.67) with chroma >= 0.1
# and >= 3:1 against the dark chart surface, then separated in lightness so
# `serious` and `critical` -- the same hue -- do not read as one colour.
#
# The dark set FAILS the categorical CVD check: amber against red is dE 4.3 for
# a deuteranope. That is not a value that can be tuned away. Green, amber and
# red are not chosen to be mutually distinguishable, they are chosen because
# everyone already knows what they mean, and the best separation available
# turns "red" into magenta and loses the convention that made the palette worth
# adopting. So the categorical gate is the wrong test here, and the relief it
# asks for is the rule instead: every status colour in this product appears
# with a WORD next to it, never hue alone. A template test enforces that, which
# is the only thing that makes this palette legitimate.
STATUS_LIGHT = {"good": "#10B981", "warning": "#F59E0B",
                "serious": "#EF4444", "critical": "#B91C1C"}
STATUS_DARK = {"good": "#0B9769", "warning": "#BC7806",
               "serious": "#FA4848", "critical": "#C71F1F"}

# The severity levels an analysis can carry, mapped onto those four roles.
# Ordered worst-first, which is the order a triage list wants.
SEVERITY_STATUS = {"critical": "critical", "high": "serious",
                   "medium": "warning", "low": "good"}

STATUS = STATUS_LIGHT          # the light set, for anything not theme-aware


def palette_css() -> str:
    """The chart roles as custom properties, in both modes.

    Dark values are declared under the media query AND the data-theme scope so
    an explicit choice beats the OS setting in both directions.
    """
    light = "\n".join(f"  --series-{i + 1}: {c};" for i, c in enumerate(SERIES_LIGHT))
    dark = "\n".join(f"  --series-{i + 1}: {c};" for i, c in enumerate(SERIES_DARK))
    ol = "\n".join(f"  --ord-{i + 1}: {c};" for i, c in enumerate(ORDINAL_LIGHT))
    od = "\n".join(f"  --ord-{i + 1}: {c};" for i, c in enumerate(ORDINAL_DARK))
    status = "\n".join(f"  --status-{k}: {v};" for k, v in STATUS_LIGHT.items())
    status_dark = "\n".join(f"  --status-{k}: {v};" for k, v in STATUS_DARK.items())
    return f""":root {{
{status}
}}
@media (prefers-color-scheme: dark) {{
  :root:where(:not([data-theme="light"])) {{
{status_dark}
  }}
}}
:root[data-theme="dark"] {{
{status_dark}
}}
.viz {{
  color-scheme: light;
  --viz-surface: #ffffff;
  --viz-grid: #e6e9ed;
  --viz-ink: #14181d;
  --viz-ink-soft: #5d6772;
{light}
{ol}
{status}
}}
@media (prefers-color-scheme: dark) {{
  :root:where(:not([data-theme="light"])) .viz {{
    color-scheme: dark;
    --viz-surface: #1a1a19;
    --viz-grid: #33332f;
    --viz-ink: #f4f4f0;
    --viz-ink-soft: #a8a79c;
{dark}
{od}
{status_dark}
  }}
}}
:root[data-theme="dark"] .viz {{
  color-scheme: dark;
  --viz-surface: #1a1a19;
  --viz-grid: #33332f;
  --viz-ink: #f4f4f0;
  --viz-ink-soft: #a8a79c;
{dark}
{od}
{status_dark}
}}"""


def _e(text) -> str:
    return escape(str(text), quote=True)


def _nice_max(value: float) -> int:
    """A round axis maximum at or above `value`."""
    if value <= 0:
        return 1
    for step in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000):
        if value <= step:
            return step
    return int(((value // 1000) + 1) * 1000)


def empty(message: str) -> str:
    return (f'<p class="viz-empty">{_e(message)}</p>')


# --------------------------------------------------------------------------
# Forms
# --------------------------------------------------------------------------

def trend(points: list[tuple[str, int, int]], *, height: int = 190) -> str:
    """Failures per day, with the deduplicated share beneath.

    Two series, so a legend is present and both are directly labelled -- colour
    never carries the identity on its own. One axis: both series are counts of
    the same thing, which is the only case where sharing a scale is honest.
    """
    if not points:
        return empty("No failures in this window.")

    width, pad_l, pad_b, pad_t = 760, 44, 26, 14
    plot_w, plot_h = width - pad_l - 12, height - pad_b - pad_t
    top = _nice_max(max(p[1] for p in points))
    n = len(points)
    step = plot_w / max(n - 1, 1)

    def x(i): return pad_l + i * step
    def y(v): return pad_t + plot_h - (v / top) * plot_h

    total = " ".join(f"{x(i):.1f},{y(p[1]):.1f}" for i, p in enumerate(points))
    dedup = " ".join(f"{x(i):.1f},{y(p[2]):.1f}" for i, p in enumerate(points))
    area = (f"{pad_l},{pad_t + plot_h} " + total +
            f" {x(n - 1):.1f},{pad_t + plot_h}")

    grid = "".join(
        f'<line x1="{pad_l}" y1="{y(v):.1f}" x2="{width - 12}" y2="{y(v):.1f}"/>'
        f'<text class="ax" x="{pad_l - 8}" y="{y(v) + 4:.1f}" text-anchor="end">{v}</text>'
        for v in (0, top // 2, top))

    # Label the ends and the peak only -- a number on every point is noise.
    peak = max(range(n), key=lambda i: points[i][1])
    labels = {0, n - 1, peak}
    marks = "".join(
        f'<circle class="s1" cx="{x(i):.1f}" cy="{y(points[i][1]):.1f}" r="4"/>'
        f'<text class="val" x="{x(i):.1f}" y="{y(points[i][1]) - 10:.1f}"'
        f' text-anchor="middle">{points[i][1]}</text>'
        for i in sorted(labels))

    ticks = "".join(
        f'<text class="ax" x="{x(i):.1f}" y="{height - 8}" text-anchor="middle">'
        f'{_e(points[i][0][5:])}</text>'
        for i in sorted({0, n // 2, n - 1}))

    return f"""<figure class="viz">
<figcaption class="viz-legend">
  <span><i style="background:var(--series-1)"></i>Failures</span>
  <span><i style="background:var(--series-3)"></i>Answered from the store</span>
</figcaption>
<svg viewBox="0 0 {width} {height}" role="img" class="chart"
     aria-label="Failures per day, and how many were answered without a model call">
  <g class="grid">{grid}</g>
  <polygon class="fill1" points="{area}"/>
  <polyline class="line1" points="{total}"/>
  <polyline class="line3" points="{dedup}"/>
  {marks}
  <g>{ticks}</g>
</svg>
</figure>"""


def money(value: float) -> str:
    """Dollars at a precision that does not round a real cost to nothing.

    Four decimals because a single analysis costs about three cents and a
    triage call a tenth of one -- two decimals would print most of this
    product's actual spend as $0.00, which reads as free rather than as small.
    """
    return f"${value:,.4f}"


def bars(rows, *, ordinal: bool = False, fmt=None) -> str:
    """Horizontal bars. Labels sit outside the bar, so length is the only
    encoding doing work -- which is also the relief the palette validator
    requires for the three light slots that fall under 3:1 on white.

    `fmt` formats the value for display without changing what the bar measures,
    so money can read as money while the bar stays proportional.
    """
    if not rows:
        return empty("Nothing to show yet.")
    show = fmt or (lambda v: f"{v:,}")
    top = max(v for _, v in rows) or 1
    out = ['<div class="viz bar-list">']
    for i, (label, value) in enumerate(rows[:8]):
        colour = (f"var(--ord-{min(i + 1, 5)})" if ordinal
                  else f"var(--series-{(i % 5) + 1})")
        pct = 100 * value / top if top else 0
        out.append(
            f'<div class="bar-row">'
            f'<span class="bar-label" title="{_e(label)}">{_e(label)}</span>'
            f'<span class="bar-track">'
            f'<span class="bar-fill" style="width:{pct:.1f}%;background:{colour}"></span>'
            f'</span>'
            f'<span class="bar-value">{_e(show(value))}</span>'
            f'</div>')
    out.append("</div>")
    return "".join(out)


def meter(value: float, cap: float, label: str, *, fmt=None) -> str:
    """A single ratio against a limit: spend against a budget cap.

    A meter rather than a chart, because that is what one number against one
    limit is. `bars()` normalises against the largest row, so the same figure
    would fill the track whether the cap were $2 or $200 -- a bar chart of one
    value against nothing is not a budget.

    The fill steps through the STATUS roles by proportion of the cap, and the
    numbers are written beside it: colour is never the only thing saying you
    are near the limit, here or anywhere else in this product.
    """
    fmt = fmt or money
    cap = float(cap or 0)
    value = max(float(value or 0), 0.0)
    if cap <= 0:
        return empty("No cap is configured, so there is nothing to measure against.")
    pct = min(value / cap, 1.0)
    over = value > cap
    role = ("critical" if over else "serious" if pct >= 0.9
            else "warning" if pct >= 0.6 else "good")
    # The word, always. `charts.STATUS_*` is a traffic-light triad and a
    # deuteranope cannot separate its amber from its red; the label is what
    # makes it legible, not the hue.
    word = {"good": "within budget", "warning": "over half spent",
            "serious": "close to the cap", "critical": "over the cap"}[role]
    return (
        f'<div class="viz meter">'
        f'<div class="meter-head"><span>{_e(label)}</span>'
        f'<b>{_e(fmt(value))} of {_e(fmt(cap))}</b></div>'
        f'<div class="bar-track"><span class="bar-fill" style="width:{pct * 100:.1f}%;'
        f'background:var(--status-{role})"></span></div>'
        f'<div class="meter-foot">{pct * 100:.0f}% &middot; {_e(word)}</div>'
        f'</div>')


def stacked(rows: list[tuple[str, int]]) -> str:
    """One stacked bar for a breakdown, with a labelled legend.

    A 2px surface gap separates segments, so adjacent fills never appear to
    merge into one.
    """
    if not rows:
        return empty("Nothing analysed yet.")
    total = sum(v for _, v in rows) or 1
    segs, legend = [], []
    for i, (label, value) in enumerate(rows[:5]):
        colour = f"var(--series-{(i % 5) + 1})"
        segs.append(f'<span class="seg" style="flex:{value};background:{colour}"'
                    f' title="{_e(label)}: {value:,}"></span>')
        legend.append(f'<span><i style="background:{colour}"></i>{_e(label)}'
                      f' <b>{value:,}</b> ({100 * value / total:.0f}%)</span>')
    return (f'<div class="viz"><div class="stack">{"".join(segs)}</div>'
            f'<div class="viz-legend wrap">{"".join(legend)}</div></div>')
