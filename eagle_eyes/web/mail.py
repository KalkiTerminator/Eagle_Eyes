"""Mail configuration for the hosted product, and the send it performs.

Dry-run is the default and stays the default until an SMTP host AND a sender
are both configured. That ordering matters: a half-configured relay that
silently falls back to sending from a default address is how an automated
system ends up mailing real developers from a demo instance.

Everything reads the environment on each call rather than at import, so the
relay can be turned on, off or repointed by restarting one worker -- the same
property the budget kill switch has and for the same reason.
"""
from __future__ import annotations

import os

from ..notify import Notifier
from ..storage import Database, NotificationStateRepo, Principal

HOST_VAR = "EAGLE_EYES_SMTP_HOST"
PORT_VAR = "EAGLE_EYES_SMTP_PORT"
USER_VAR = "EAGLE_EYES_SMTP_USER"
PASSWORD_VAR = "EAGLE_EYES_SMTP_PASSWORD"
SENDER_VAR = "EAGLE_EYES_SMTP_SENDER"
STARTTLS_VAR = "EAGLE_EYES_SMTP_STARTTLS"
BASE_URL_VAR = "EAGLE_EYES_BASE_URL"

DEFAULT_PORT = 587          # the submission port, which offers STARTTLS


def configured(env: dict[str, str] | None = None) -> bool:
    """Whether a real relay is set up. False means dry-run, always."""
    env = env if env is not None else os.environ
    return bool((env.get(HOST_VAR) or "").strip()
                and (env.get(SENDER_VAR) or "").strip())


def _port(env: dict[str, str]) -> int:
    raw = (env.get(PORT_VAR) or "").strip()
    try:
        port = int(raw)
    except ValueError:
        return DEFAULT_PORT
    return port if 1 <= port <= 65535 else DEFAULT_PORT


def notifier_for(db: Database, principal: Principal,
                 env: dict[str, str] | None = None) -> Notifier:
    """A Notifier whose suppression survives this request.

    The store is the DURABLE one. With the in-memory store a new Notifier is
    built per request, so "already notified in the last 24 hours" and "ten an
    hour" both reset on every click -- the hourly cap would permit ten mails
    per request, which is not a cap. See storage.NotificationStateRepo.
    """
    env = env if env is not None else dict(os.environ)
    live = configured(env)
    return Notifier(
        dry_run=not live,
        smtp_host=(env.get(HOST_VAR) or "").strip(),
        smtp_port=_port(env),
        sender=(env.get(SENDER_VAR) or "eagle-eyes@localhost").strip(),
        smtp_user=(env.get(USER_VAR) or "").strip(),
        smtp_password=env.get(PASSWORD_VAR) or "",
        starttls=(env.get(STARTTLS_VAR) or "1").strip().lower()
                 not in ("0", "false", "no", "off"),
        store=NotificationStateRepo(db, principal),
    )


def base_url(env: dict[str, str] | None = None) -> str:
    """Where a link in an email should point. Empty when nobody has said.

    Guessing from the request's Host header would let anyone who can reach the
    instance decide what URL its emails advertise.
    """
    env = env if env is not None else os.environ
    return (env.get(BASE_URL_VAR) or "").strip().rstrip("/")
