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
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path


@dataclass
class Notification:
    to: str
    subject: str
    body: str
    fingerprint: str
    report_path: str = ""


@dataclass
class SuppressionState:
    """In-memory for a single run; the durable version lives in the database."""
    sent: dict[tuple[str, str], datetime] = field(default_factory=dict)
    counts: dict[tuple[str, str], int] = field(default_factory=dict)
    per_hour: dict[str, list[datetime]] = field(default_factory=dict)


@dataclass
class Decision:
    send: bool
    reason: str


class Notifier:
    def __init__(self, *, dry_run: bool = True, smtp_host: str = "",
                 smtp_port: int = 25, sender: str = "eagle-eyes@localhost",
                 per_developer_hourly_cap: int = 10,
                 repeat_window_hours: int = 24,
                 min_confidence: float = 0.3) -> None:
        self.dry_run = dry_run
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.cap = per_developer_hourly_cap
        self.repeat_window = timedelta(hours=repeat_window_hours)
        self.min_confidence = min_confidence
        self.state = SuppressionState()
        self.sent_log: list[Notification] = []
        self.suppressed: list[tuple[Notification, str]] = []

    # -- suppression -------------------------------------------------------

    def decide(self, to: str, fingerprint: str, *, category: str,
               confidence: float, now: datetime | None = None) -> Decision:
        now = now or datetime.now()
        key = (to, fingerprint)

        if category == "noise":
            return Decision(False, "classified as noise")

        if confidence < self.min_confidence:
            return Decision(False, f"confidence {confidence:.2f} below threshold "
                                   f"-- held for the digest rather than sent as an answer")

        last = self.state.sent.get(key)
        if last and now - last < self.repeat_window:
            self.state.counts[key] = self.state.counts.get(key, 1) + 1
            return Decision(False, f"already notified; now seen "
                                   f"{self.state.counts[key]} times")

        recent = [t for t in self.state.per_hour.get(to, []) if now - t < timedelta(hours=1)]
        self.state.per_hour[to] = recent
        if len(recent) >= self.cap:
            return Decision(False, f"hourly cap of {self.cap} reached for {to}")

        return Decision(True, "new failure")

    def _record(self, to: str, fingerprint: str, when: datetime) -> None:
        self.state.sent[(to, fingerprint)] = when
        self.state.counts[(to, fingerprint)] = 1
        self.state.per_hour.setdefault(to, []).append(when)

    # -- sending -----------------------------------------------------------

    def send(self, n: Notification, *, category: str = "novel",
             confidence: float = 1.0, now: datetime | None = None) -> Decision:
        now = now or datetime.now()
        d = self.decide(n.to, n.fingerprint, category=category,
                        confidence=confidence, now=now)
        if not d.send:
            self.suppressed.append((n, d.reason))
            return d

        if self.dry_run:
            self.sent_log.append(n)
        else:
            msg = EmailMessage()
            msg["From"] = self.sender
            msg["To"] = n.to
            msg["Subject"] = n.subject
            msg.set_content(n.body)
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20) as s:
                s.send_message(msg)
            self.sent_log.append(n)

        self._record(n.to, n.fingerprint, now)
        return d

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
