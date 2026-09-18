"""Notifications, and the suppression that makes them tolerable.

Suppression matters more than sending. An infrastructure incident produces
hundreds of failures in minutes, and a system that emails a developer two
hundred times during one is a system they will filter to junk by lunchtime --
after which it delivers nothing at all, forever.

Rules, from docs/ARCHITECTURE.md and the notification design:

  * Noise never notifies.
  * A repeat of a fingerprint already sent notifies once, then increments a
    count instead of sending again.
  * A per-developer hourly cap, so no incident can flood one inbox.
  * A low-confidence diagnosis is suppressed to the digest rather than sent as
    if it were an answer.
  * Dry-run renders to a log instead of sending, so this is safe to exercise.

The screenshot is never attached. The mail links to the report, which links to
the file where it already sits (docs/SECURITY.md).
"""

from __future__ import annotations

import smtplib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Protocol


@dataclass
class Notification:
    to: str
    subject: str
    body: str
    fingerprint: str
    report_path: str = ""
    # An optional HTML alternative. The plain text stays the real message --
    # it is what a text client, a screen reader and a mail archive show, and a
    # diagnosis that only exists in the HTML part is a diagnosis some readers
    # never get. HTML is added as an alternative to it, never instead of it.
    html: str = ""


class SuppressionStore(Protocol):
    """Where the suppression rules read their history from.

    Every rule here is a statement about a window of time -- "already notified
    in the last 24 hours", "ten already sent this hour". A window is only as
    long as whatever holds it. Held on the Notifier, the windows are exactly as
    long as the process: one scan in the CLI, one HTTP request in a service.
    The second case makes the hourly cap send ten mails per request, which is
    no cap at all, and it is not visible in the code -- the field is called
    `per_hour` and the constructor still says `per_developer_hourly_cap=10`.

    So history comes from a store. `MemorySuppression` is the CLI's, and it is
    honest about its lifetime. `storage.NotificationStateRepo` is the durable
    one, over a table that has been in the schema since the beginning.
    """

    def last_sent(self, to: str, fingerprint: str) -> datetime | None: ...
    def seen_count(self, to: str, fingerprint: str) -> int: ...
    def bump_suppressed(self, to: str, fingerprint: str) -> int: ...
    def sent_in_last_hour(self, to: str, now: datetime) -> int: ...
    def record_sent(self, to: str, fingerprint: str, when: datetime) -> None: ...


@dataclass
class SuppressionState:
    """The raw dictionaries behind MemorySuppression."""
    sent: dict[tuple[str, str], datetime] = field(default_factory=dict)
    counts: dict[tuple[str, str], int] = field(default_factory=dict)
    per_hour: dict[str, list[datetime]] = field(default_factory=dict)


class MemorySuppression:
    """Process-lifetime suppression. Correct for one CLI run and nothing else.

    Do not use this in a server: see SuppressionStore.
    """

    durable = False

    def __init__(self, state: SuppressionState | None = None) -> None:
        self.state = state or SuppressionState()

    def last_sent(self, to: str, fingerprint: str) -> datetime | None:
        return self.state.sent.get((to, fingerprint))

    def seen_count(self, to: str, fingerprint: str) -> int:
        return self.state.counts.get((to, fingerprint), 0)

    def bump_suppressed(self, to: str, fingerprint: str) -> int:
        key = (to, fingerprint)
        self.state.counts[key] = self.state.counts.get(key, 1) + 1
        return self.state.counts[key]

    def sent_in_last_hour(self, to: str, now: datetime) -> int:
        now = _aware(now)
        recent = [t for t in self.state.per_hour.get(to, [])
                  if now - _aware(t) < timedelta(hours=1)]
        self.state.per_hour[to] = recent
        return len(recent)

    def record_sent(self, to: str, fingerprint: str, when: datetime) -> None:
        self.state.sent[(to, fingerprint)] = when
        self.state.counts[(to, fingerprint)] = 1
        self.state.per_hour.setdefault(to, []).append(when)


def _aware(t: datetime) -> datetime:
    """Callers may pass a naive `now` for testing; treat it as UTC."""
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


@dataclass
class Decision:
    send: bool
    reason: str


class Notifier:
    def __init__(self, *, dry_run: bool = True, smtp_host: str = "",
                 smtp_port: int = 25, sender: str = "eagle-eyes@localhost",
                 smtp_user: str = "", smtp_password: str = "",
                 starttls: bool = True,
                 per_developer_hourly_cap: int = 10,
                 repeat_window_hours: int = 24,
                 min_confidence: float = 0.3,
                 store: "SuppressionStore | None" = None) -> None:
        self.dry_run = dry_run
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        # On by default. An internal relay on port 25 that does not offer
        # STARTTLS is handled by the capability check at send time; defaulting
        # this to False would silently send a diagnosis, a bot name and a
        # developer's address in clear text across the estate.
        self.starttls = starttls
        self.cap = per_developer_hourly_cap
        self.repeat_window = timedelta(hours=repeat_window_hours)
        self.min_confidence = min_confidence
        self.store = store or MemorySuppression()
        self.sent_log: list[Notification] = []
        self.suppressed: list[tuple[Notification, str]] = []

    # -- suppression -------------------------------------------------------

    def decide(self, to: str, fingerprint: str, *, category: str,
               confidence: float, now: datetime | None = None) -> Decision:
        now = _aware(now or datetime.now(timezone.utc))

        if category == "noise":
            return Decision(False, "classified as noise")

        if confidence < self.min_confidence:
            return Decision(False, f"confidence {confidence:.2f} below threshold "
                                   f"-- held for the digest rather than sent as an answer")

        last = self.store.last_sent(to, fingerprint)
        if last and now - _aware(last) < self.repeat_window:
            seen = self.store.bump_suppressed(to, fingerprint)
            return Decision(False, f"already notified; now seen {seen} times")

        if self.store.sent_in_last_hour(to, now) >= self.cap:
            return Decision(False, f"hourly cap of {self.cap} reached for {to}")

        return Decision(True, "new failure")

    @property
    def state(self) -> SuppressionState:
        """The raw in-memory state, for tests and the CLI digest.

        Raises for a durable store: there is no dictionary to hand back, and
        returning an empty one would read as "nothing has been sent".
        """
        if isinstance(self.store, MemorySuppression):
            return self.store.state
        raise AttributeError(
            f"{type(self.store).__name__} keeps suppression state in the database, "
            "not in a dictionary. Query the store instead.")

    def _record(self, to: str, fingerprint: str, when: datetime) -> None:
        self.store.record_sent(to, fingerprint, _aware(when))

    # -- sending -----------------------------------------------------------

    def send(self, n: Notification, *, category: str = "novel",
             confidence: float = 1.0, now: datetime | None = None) -> Decision:
        now = _aware(now or datetime.now(timezone.utc))
        d = self.decide(n.to, n.fingerprint, category=category,
                        confidence=confidence, now=now)
        if not d.send:
            self.suppressed.append((n, d.reason))
            return d

        if self.dry_run:
            self.sent_log.append(n)
        else:
            self._relay(self.build_message(n))
            self.sent_log.append(n)

        self._record(n.to, n.fingerprint, now)
        return d

    def build_message(self, n: Notification) -> EmailMessage:
        """The MIME message, built the same way whether or not it is sent.

        Separate from `_relay` so a dry run and a real send produce the same
        bytes -- a dry run that exercises a different code path is not a
        rehearsal of anything.
        """
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = n.to
        msg["Subject"] = n.subject
        msg.set_content(n.body)
        if n.html:
            msg.add_alternative(n.html, subtype="html")
        return msg

    def _relay(self, msg: EmailMessage) -> None:
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20) as s:
            s.ehlo()
            if self.starttls and s.has_extn("starttls"):
                s.starttls()
                s.ehlo()                      # capabilities change after upgrade
            if self.smtp_user:
                # Only after the upgrade, and only when the relay wants one --
                # sending AUTH on a plaintext connection hands over the
                # password. A relay that takes credentials and offers no
                # STARTTLS is a misconfiguration to fix, not to work around.
                if self.starttls and not s.has_extn("starttls"):
                    raise RuntimeError(
                        f"{self.smtp_host}:{self.smtp_port} does not offer STARTTLS "
                        "and credentials were configured. Refusing to send the "
                        "password in clear text. Fix the relay, or set "
                        "EAGLE_EYES_SMTP_STARTTLS=0 knowingly for a trusted "
                        "internal relay with no credentials.")
                s.login(self.smtp_user, self.smtp_password)
            s.send_message(msg)

    def digest(self) -> str:
        """What was held back, so suppression is visible rather than silent."""
        if not self.suppressed:
            return "Nothing suppressed."
        by_reason: dict[str, int] = {}
        for _, reason in self.suppressed:
            head = reason.split(";")[0].split("--")[0].strip()
            by_reason[head] = by_reason.get(head, 0) + 1
        lines = [f"{len(self.suppressed)} notifications suppressed:"]
        lines += [f"  {n:>4}  {reason}" for reason, n in
                  sorted(by_reason.items(), key=lambda kv: -kv[1])]
        return "\n".join(lines)


def compose(*, to: str, bot_label: str, exception_type: str, root_cause: str,
            suggested_fix: str, confidence: float, fingerprint: str,
            report_path: str | Path = "") -> Notification:
    short = exception_type.split(".")[-1]
    body = f"""{bot_label} failed: {short}

WHAT WENT WRONG
{root_cause}

SUGGESTED FIX
{suggested_fix}

Confidence: {confidence:.2f}{'  -- treat as a lead, not an answer' if confidence < 0.5 else ''}

Full report (including a link to the screenshot, which opens with your existing
access -- it is not attached to this mail):
{report_path or '(no report written)'}

This is an automated diagnosis and can be wrong.
Marking it correct, partial or wrong is what stops a bad analysis reaching
the next person.
"""
    return Notification(to=to, subject=f"[Eagle Eyes] {bot_label}: {short}",
                        body=body, fingerprint=fingerprint,
                        report_path=str(report_path))


# Severity -> (label, colour). The LIGHT status values from web/charts.py,
# repeated here as a literal rather than imported: notify.py is the CLI's, and
# the CLI must not depend on the web package. A test asserts the two agree, so
# the copy cannot drift silently.
#
# Light only, and every badge carries the WORD as well as the colour. Mail
# clients invert, re-theme and strip styles unpredictably, and a severity that
# survives only as a background colour does not survive at all -- which is the
# same rule the product's own pages follow, for a different reason.
SEVERITY_COLOUR = {
    "critical": ("CRITICAL", "#B91C1C"),
    "high":     ("HIGH",     "#EF4444"),
    "medium":   ("MEDIUM",   "#F59E0B"),
    "low":      ("LOW",      "#10B981"),
}


def compose_html(*, bot_label: str, exception_type: str, root_cause: str,
                 suggested_fix: str, confidence: float, severity: str = "",
                 failure_type: str = "", affected_function: str = "",
                 recommendations: str = "", report_url: str = "",
                 path: str = "") -> str:
    """The HTML alternative: an internal work email, not a newsletter.

    Every style is inline. Mail clients strip <style> blocks, ignore external
    sheets and rewrite classes, so a stylesheet here means the diagnosis
    arrives as unstyled text at some fraction of recipients and there is no way
    to find out which.
    """
    from html import escape

    def e(v) -> str:
        return escape(str(v or ""), quote=True)

    short = exception_type.split(".")[-1] or "Failure"
    label, colour = SEVERITY_COLOUR.get(severity, ("", ""))
    badge = ""
    if label:
        badge = (f'<span style="display:inline-block;padding:3px 10px;border-radius:3px;'
                 f'background:{colour};color:#ffffff;font-size:12px;font-weight:700;'
                 f'letter-spacing:.06em">{label}</span>')

    meta = [("Bot", bot_label), ("Exception", short)]
    if failure_type:
        meta.append(("Type", failure_type.replace("_", " ")))
    meta.append(("Confidence", f"{confidence:.2f}"
                 + ("  — a lead, not an answer" if confidence < 0.5 else "")))
    if affected_function:
        meta.append(("Affected function", affected_function))
    if path:
        meta.append(("Answered by", "the known-pattern library" if path == "template"
                     else f"a model ({path})"))
    rows = "".join(
        f'<tr><td style="padding:4px 14px 4px 0;color:#666;font-size:13px;'
        f'white-space:nowrap">{e(k)}</td>'
        f'<td style="padding:4px 0;font-size:13px">{e(v)}</td></tr>'
        for k, v in meta)

    extra = ""
    if recommendations:
        extra = (f'<h3 style="margin:26px 0 6px;font-size:14px;letter-spacing:.04em;'
                 f'text-transform:uppercase;color:#666">Also worth doing</h3>'
                 f'<p style="margin:0;font-size:14px;line-height:1.55">'
                 f'{e(recommendations)}</p>')

    link = ""
    if report_url:
        link = (f'<p style="margin:26px 0 0;font-size:14px">'
                f'<a href="{e(report_url)}" style="color:#2a78d6">Open the full report</a>'
                f' — including the screenshot, which opens with your existing access '
                f'and is not attached to this mail.</p>')

    return f"""<!doctype html>
<html><body style="margin:0;padding:24px;background:#f6f6f4;
  font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a">
<div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e0e0e0;
  border-radius:6px;padding:28px">

  <p style="margin:0 0 4px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;
    color:#666">Eagle Eyes — automated diagnosis</p>
  <h1 style="margin:0 0 14px;font-size:20px;line-height:1.3">{e(bot_label)} failed: {e(short)}</h1>
  {badge}

  <h2 style="margin:26px 0 6px;font-size:14px;letter-spacing:.04em;
    text-transform:uppercase;color:#666">What went wrong</h2>
  <p style="margin:0;font-size:15px;line-height:1.6">{e(root_cause)}</p>

  <h2 style="margin:26px 0 6px;font-size:14px;letter-spacing:.04em;
    text-transform:uppercase;color:#666">Suggested fix</h2>
  <div style="margin:0;padding:14px 16px;background:#f6f6f4;border-left:3px solid #2a78d6;
    font-size:14px;line-height:1.6;white-space:pre-wrap">{e(suggested_fix)}</div>

  {extra}

  <table style="margin:26px 0 0;border-collapse:collapse">{rows}</table>
  {link}

  <p style="margin:26px 0 0;padding-top:16px;border-top:1px solid #e0e0e0;
    font-size:12px;line-height:1.6;color:#666">
    This is an automated analysis and it can be wrong. Review it before applying
    anything. Marking it correct, partial or wrong in Eagle Eyes is what stops a
    bad diagnosis reaching the next person who hits this failure.
  </p>
</div></body></html>"""
