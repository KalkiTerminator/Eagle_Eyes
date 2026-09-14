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
                 per_developer_hourly_cap: int = 10,
                 repeat_window_hours: int = 24,
                 min_confidence: float = 0.3,
                 store: "SuppressionStore | None" = None) -> None:
        self.dry_run = dry_run
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
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
