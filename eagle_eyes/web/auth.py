"""Identity, sessions and the account lifecycle.

Standard library only -- `hashlib.scrypt` for passwords, `hmac` and `secrets`
for sessions. No auth library, because nothing here is unusual enough to need
one and a dependency in the authentication path is a dependency you have to
keep watching.

THE RULE THIS MODULE EXISTS TO ENFORCE: signing in and being allowed to see
something are different questions.

Registration creates an account that can sign in immediately and see nothing.
An admin then approves it with a role, and for a manager a scope of teams.
Conflating the two is how an account nobody reviewed ends up reading failures
-- so `Account.principal()` refuses to produce a Principal for any status other
than `approved`, and every repository in `storage.py` already requires one.
Route decorators are a convenience on top of that; the data layer is the
boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import storage
from ..storage import (
    ADMIN, MANAGER, USER, AccessDenied, Database, DeveloperRepo, Principal,
    Repository, now,
)

# --------------------------------------------------------------------------
# Passwords
#
# scrypt parameters. n=2**14 with r=8, p=1 is ~16MB and a few tens of
# milliseconds -- slow enough to matter against an offline attack, fast enough
# that a sign-in does not feel broken. `params` is stored per row so these can
# be raised later and each password re-hashed on its next successful sign-in,
# rather than invalidating everyone's password at once.
# --------------------------------------------------------------------------

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

# Long enough to be worth something, short enough that nobody writes it down.
MIN_PASSWORD = 12
MAX_PASSWORD = 1024          # scrypt on an unbounded input is a free CPU burn

SESSION_TTL = timedelta(hours=12)
SESSION_COOKIE = "ee_session"

MAX_FAILED_LOGINS = 8
LOCKOUT = timedelta(minutes=15)

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(Exception):
    """Anything that should be reported to the user as a failed sign-in.

    Deliberately one type. Distinguishing "no such account" from "wrong
    password" in the response tells an attacker which emails are registered.
    """


def _params() -> str:
    return json.dumps({"alg": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P})


def hash_password(password: str, salt: str | None = None,
                  params: str | None = None) -> tuple[str, str, str]:
    """Returns (hash_hex, salt_hex, params_json)."""
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"password must be at least {MIN_PASSWORD} characters")
    if len(password) > MAX_PASSWORD:
        raise AuthError(f"password must be at most {MAX_PASSWORD} characters")
    salt = salt or secrets.token_hex(16)
    cfg = json.loads(params) if params else json.loads(_params())
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=bytes.fromhex(salt),
        n=cfg["n"], r=cfg["r"], p=cfg["p"], maxmem=SCRYPT_MAXMEM, dklen=64)
    return digest.hex(), salt, params or _params()


def verify_password(password: str, stored_hash: str, salt: str, params: str) -> bool:
    try:
        candidate, _, _ = hash_password(password, salt, params)
    except (AuthError, ValueError, KeyError):
        return False
    return hmac.compare_digest(candidate, stored_hash)


# --------------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------------

REQUESTED, APPROVED, SUSPENDED, REVOKED = (
    "requested", "approved", "suspended", "revoked")


@dataclass(frozen=True)
class Account:
    id: int
    email: str
    display_name: str
    status: str
    role: str
    scope: frozenset[str]
    developer_id: int | None = None

    @property
    def may_sign_in(self) -> bool:
        """Revoked accounts cannot sign in. Everyone else can -- and may see nothing."""
        return self.status in (REQUESTED, APPROVED, SUSPENDED)

    @property
    def is_approved(self) -> bool:
        return self.status == APPROVED

    def principal(self) -> Principal:
        """The identity the data layer will accept.

        Refuses for anything but `approved`. This is the single place where
        "has an account" becomes "may read data", and it is a raise rather than
        a falsy return so that a caller which forgets to check gets an error
        instead of a Principal with no scope that quietly reads nothing --
        or worse, one that defaults open.
        """
        if self.status != APPROVED:
            raise AccessDenied(
                f"account {self.email} is '{self.status}', not approved. "
                "Signing in and being granted access are separate steps.")
        return Principal(actor=self.email, role=self.role, scope=self.scope)


class AccountRepo(Repository):
    """Accounts, their approval state and their scope.

    Note what this repository does NOT do: it never returns a Principal for an
    unapproved account, and it never widens a scope as a side effect of a login.
    """

    # -- registration --------------------------------------------------

    def register(self, email: str, password: str, display_name: str = "") -> int:
        """Create a `requested` account. Grants nothing."""
        email = _clean_email(email)
        pw_hash, salt, params = hash_password(password)
        try:
            cur = self.db.conn.execute(
                "INSERT INTO account(email, display_name, password_hash, salt, params,"
                " status, role, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (email, display_name.strip() or email.split("@")[0],
                 pw_hash, salt, params, REQUESTED, USER, now()))
        # storage.INTEGRITY_ERRORS, not a name imported from it: the tuple grows
        # when storage_pg registers psycopg's type, and `from x import y` would
        # have captured whatever it held at import time. A stale tuple here
        # turns a taken email address into a 500 -- which is also an answer to
        # "is this address registered".
        except storage.INTEGRITY_ERRORS:
            # Do not say whether the address is taken -- that is a free
            # membership oracle for anyone with a list of emails.
            raise AuthError("registration could not be completed") from None
        self._audit("register", "account", cur.lastrowid)
        return cur.lastrowid

    # -- lookup --------------------------------------------------------

    def by_email(self, email: str) -> Account | None:
        row = self.db.conn.execute(
            "SELECT * FROM account WHERE email=?", (_clean_email(email),)).fetchone()
        return self._build(row) if row else None

    def by_id(self, account_id: int) -> Account | None:
        row = self.db.conn.execute(
            "SELECT * FROM account WHERE id=?", (account_id,)).fetchone()
        return self._build(row) if row else None

    def _build(self, row: sqlite3.Row) -> Account:
        scope = {r["name"] for r in self.db.conn.execute(
            "SELECT t.name FROM account_scope s JOIN team t ON t.id=s.team_id"
            " WHERE s.account_id=?", (row["id"],))}
        return Account(
            id=row["id"], email=row["email"], display_name=row["display_name"],
            status=row["status"], role=row["role"], scope=frozenset(scope),
            developer_id=row["developer_id"])

    def list_all(self, status: str | None = None) -> list[Account]:
        if not self.p.is_admin:
            raise AccessDenied("only an admin may list accounts")
        sql = "SELECT * FROM account"
        args: tuple[Any, ...] = ()
        if status:
            sql += " WHERE status=?"
            args = (status,)
        sql += " ORDER BY created_at DESC"
        return [self._build(r) for r in self.db.conn.execute(sql, args)]

    # -- authentication ------------------------------------------------

    def authenticate(self, email: str, password: str) -> Account:
        """Verify a password. Says nothing about what the account may do.

        Runs the scrypt work even when the account does not exist, so the
        response time does not distinguish a real address from a made-up one.
        """
        row = self.db.conn.execute(
            "SELECT * FROM account WHERE email=?", (_clean_email(email),)).fetchone()

        if row is None:
            hash_password(password if len(password) >= MIN_PASSWORD
                          else password.ljust(MIN_PASSWORD, "x"))
            raise AuthError("email or password is incorrect")

        locked = row["locked_until"]
        if locked and locked > now():
            raise AuthError("too many failed attempts; try again shortly")

        if not verify_password(password, row["password_hash"], row["salt"], row["params"]):
            failed = row["failed_logins"] + 1
            lock = (_stamp(datetime.now(timezone.utc) + LOCKOUT)
                    if failed >= MAX_FAILED_LOGINS else None)
            self.db.conn.execute(
                "UPDATE account SET failed_logins=?, locked_until=? WHERE id=?",
                (failed, lock, row["id"]))
            self.db.conn.execute(
                "INSERT INTO audit_event(actor, actor_role, action, resource_type,"
                " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
                (row["email"], row["role"], "login", "account", str(row["id"]),
                 "deny", now()))
            raise AuthError("email or password is incorrect")

        account = self._build(row)
        if not account.may_sign_in:
            self.db.conn.execute(
                "INSERT INTO audit_event(actor, actor_role, action, resource_type,"
                " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
                (row["email"], row["role"], "login", "account", str(row["id"]),
                 "deny", now()))
            raise AuthError("this account has been revoked")

        self.db.conn.execute(
            "UPDATE account SET failed_logins=0, locked_until=NULL, last_login_at=?"
            " WHERE id=?", (now(), row["id"]))
        self.db.conn.execute(
            "INSERT INTO audit_event(actor, actor_role, action, resource_type,"
            " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
            (row["email"], row["role"], "login", "account", str(row["id"]),
             "allow", now()))
        return account

    # -- administration ------------------------------------------------

    def approve(self, account_id: int, *, role: str,
                scope: frozenset[str] | set[str] = frozenset()) -> Account:
        """Grant a role. The only way an account becomes usable."""
        self._require_admin("approve")
        if role not in (ADMIN, MANAGER, USER):
            raise ValueError(f"role must be admin/manager/user, got {role!r}")
        if role == MANAGER and not scope:
            raise ValueError(
                "a manager with an empty scope can see nothing, which is almost "
                "certainly not what was meant. Name the teams, or approve as a user.")
        if role != MANAGER and scope:
            raise ValueError(
                f"scope is meaningless for role '{role}' -- an admin sees "
                "everything and a user sees their own. Storing it would imply "
                "a restriction that is not enforced.")
        if not self.by_id(account_id):
            raise LookupError(f"no account {account_id}")

        with self.db.tx() as c:
            c.execute(
                "UPDATE account SET status=?, role=?, approved_by=?, approved_at=?"
                " WHERE id=?", (APPROVED, role, self.p.actor, now(), account_id))
            c.execute("DELETE FROM account_scope WHERE account_id=?", (account_id,))
            for team in sorted(scope):
                team_id = DeveloperRepo(self.db, self.p)._team_id(team)
                c.execute(
                    "INSERT INTO account_scope(account_id, team_id, granted_by, granted_at)"
                    " VALUES (?,?,?,?)", (account_id, team_id, self.p.actor, now()))
        self._audit("approve", "account", account_id)
        return self.by_id(account_id)

    def set_status(self, account_id: int, status: str) -> Account:
        self._require_admin("change account status")
        if status not in (REQUESTED, APPROVED, SUSPENDED, REVOKED):
            raise ValueError(f"unknown status {status!r}")
        if status == APPROVED:
            raise ValueError("use approve(), which requires a role")
        account = self.by_id(account_id)
        if not account:
            raise LookupError(f"no account {account_id}")
        if account.role == ADMIN and status in (SUSPENDED, REVOKED):
            remaining = self.db.conn.execute(
                "SELECT COUNT(*) n FROM account WHERE role=? AND status=? AND id<>?",
                (ADMIN, APPROVED, account_id)).fetchone()["n"]
            if remaining == 0:
                raise ValueError(
                    "this is the last active admin. Removing it locks everyone "
                    "out of approvals permanently; promote another admin first.")
        self.db.conn.execute("UPDATE account SET status=? WHERE id=?",
                             (status, account_id))
        # Access should stop now, not when a cookie happens to expire.
        SessionRepo(self.db, self.p).revoke_all(account_id)
        self._audit(f"status:{status}", "account", account_id)
        return self.by_id(account_id)

    def link_developer(self, account_id: int, email: str | None = None) -> int:
        """Tie an account to the developer record that owns bots and gets mail."""
        self._require_admin("link a developer")
        account = self.by_id(account_id)
        if not account:
            raise LookupError(f"no account {account_id}")
        dev_id = DeveloperRepo(self.db, self.p).ensure(email or account.email,
                                                       display_name=account.display_name)
        self.db.conn.execute("UPDATE account SET developer_id=? WHERE id=?",
                             (dev_id, account_id))
        self._audit("link_developer", "account", account_id)
        return dev_id

    def change_password(self, account_id: int, old: str, new: str) -> None:
        """An account may change its own password; an admin may not set one.

        An admin who can set a password can sign in as anyone and leave an audit
        trail that reads like that person acting. Resets belong behind an
        out-of-band channel, not behind the admin page.
        """
        account = self.by_id(account_id)
        if not account:
            raise LookupError(f"no account {account_id}")
        if account.email != self.p.actor:
            raise AccessDenied(
                "a password can only be changed by its owner. An admin who can "
                "set passwords can act as any user, which the audit log would "
                "then record as that user.")
        self.authenticate(account.email, old)
        pw_hash, salt, params = hash_password(new)
        self.db.conn.execute(
            "UPDATE account SET password_hash=?, salt=?, params=? WHERE id=?",
            (pw_hash, salt, params, account_id))
        SessionRepo(self.db, self.p).revoke_all(account_id)
        self._audit("change_password", "account", account_id)

    def _require_admin(self, what: str) -> None:
        if not self.p.is_admin:
            self._audit(what, "account", "-", outcome="deny")
            raise AccessDenied(f"only an admin may {what}")


def _clean_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not _EMAIL.match(email):
        raise AuthError("that does not look like an email address")
    if len(email) > 254:
        raise AuthError("that email address is too long")
    return email


def _stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Sessions
#
# The cookie carries `<session_id>.<hmac>`. The signature stops anyone minting
# an id; the database row is what actually decides. Role and status are read
# from the account on every request and never from the cookie, so a suspension
# takes effect on the next request rather than whenever the cookie expires --
# and a forged or edited cookie cannot claim a role, because the cookie does
# not carry one.
# --------------------------------------------------------------------------

class SessionRepo(Repository):
    def __init__(self, db: Database, principal: Principal,
                 secret: bytes | None = None) -> None:
        super().__init__(db, principal)
        self.secret = secret or b""

    def create(self, account_id: int, user_agent: str = "",
               ttl: timedelta = SESSION_TTL) -> str:
        sid = secrets.token_hex(32)
        self.db.conn.execute(
            "INSERT INTO session(id, account_id, created_at, expires_at,"
            " last_seen_at, user_agent) VALUES (?,?,?,?,?,?)",
            (sid, account_id, now(), _stamp(datetime.now(timezone.utc) + ttl),
             now(), (user_agent or "")[:300]))
        return sid

    def lookup(self, sid: str) -> int | None:
        """The account id behind a live session, or None."""
        row = self.db.conn.execute(
            "SELECT account_id, expires_at, revoked_at FROM session WHERE id=?",
            (sid,)).fetchone()
        if not row or row["revoked_at"] or row["expires_at"] <= now():
            return None
        self.db.conn.execute("UPDATE session SET last_seen_at=? WHERE id=?",
                             (now(), sid))
        return row["account_id"]

    def revoke(self, sid: str) -> None:
        self.db.conn.execute(
            "UPDATE session SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
            (now(), sid))

    def revoke_all(self, account_id: int) -> int:
        cur = self.db.conn.execute(
            "UPDATE session SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
            (now(), account_id))
        return cur.rowcount

    def purge_expired(self) -> int:
        cur = self.db.conn.execute(
            "DELETE FROM session WHERE expires_at <= ?", (now(),))
        return cur.rowcount


def sign_cookie(sid: str, secret: bytes) -> str:
    mac = hmac.new(secret, sid.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{sid}.{mac}"


def read_cookie(value: str, secret: bytes) -> str | None:
    """The session id inside a cookie, or None if it was not signed by us."""
    if not value or "." not in value:
        return None
    sid, _, mac = value.rpartition(".")
    if not sid or not mac:
        return None
    expected = hmac.new(secret, sid.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        return None
    return sid


# --------------------------------------------------------------------------
# Bootstrap
# --------------------------------------------------------------------------

BOOTSTRAP_EMAIL_VAR = "EAGLE_EYES_ADMIN_EMAIL"
BOOTSTRAP_PASSWORD_VAR = "EAGLE_EYES_ADMIN_PASSWORD"


def bootstrap_admin(db: Database, email: str, password: str,
                    display_name: str = "") -> Account:
    """Make the account at `email` the first admin, once.

    Every approval flows from an admin, so a fresh database has no way in until
    one exists. This is that way in, and it is deliberately narrow: it does
    nothing at all once any admin account exists, so it cannot be used to add a
    second admin by setting an environment variable on a running deployment.

    THE ADDRESS MAY ALREADY BE REGISTERED, and that is the common case rather
    than an edge one: somebody deploys, opens the site, signs up, and only then
    realises nobody can approve them. That used to raise a UNIQUE violation
    which nothing caught, so setting the variable to your own address
    crash-looped the container with a database error that read nothing like
    "you already registered".

    So an existing account is PROMOTED -- and its password is reset to the one
    in the environment. Promoting without resetting would hand admin to
    whoever registered that address first, which on a public URL is not
    necessarily the operator. Whoever sets the variables controls the
    credential; that is the whole basis on which this is safe.

    Either way it is written to the audit log with an actor of `bootstrap`, so
    the first admin's existence is a recorded event rather than something that
    quietly appeared.
    """
    existing = db.conn.execute(
        "SELECT COUNT(*) n FROM account WHERE role=?", (ADMIN,)).fetchone()["n"]
    if existing:
        raise AuthError(
            "an admin already exists; bootstrap does nothing. Add further "
            "admins by approving a registration, which is auditable.")

    email = _clean_email(email)
    pw_hash, salt, params = hash_password(password)
    row = db.conn.execute(
        "SELECT id FROM account WHERE email=?", (email,)).fetchone()

    with db.tx() as c:
        if row:
            account_id, action = row["id"], "bootstrap_promote"
            c.execute(
                "UPDATE account SET status=?, role=?, password_hash=?, salt=?,"
                " params=?, approved_by=?, approved_at=?, failed_logins=0,"
                " locked_until=NULL WHERE id=?",
                (APPROVED, ADMIN, pw_hash, salt, params, "bootstrap", now(),
                 account_id))
            # The password just changed, so anything signed in under the old
            # one stops working now rather than at its own expiry.
            c.execute(
                "UPDATE session SET revoked_at=? WHERE account_id=?"
                " AND revoked_at IS NULL", (now(), account_id))
        else:
            cur = c.execute(
                "INSERT INTO account(email, display_name, password_hash, salt, params,"
                " status, role, approved_by, approved_at, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (email, display_name.strip() or email.split("@")[0], pw_hash, salt,
                 params, APPROVED, ADMIN, "bootstrap", now(), now()))
            account_id, action = cur.lastrowid, "bootstrap_admin"

        c.execute(
            "INSERT INTO audit_event(actor, actor_role, action, resource_type,"
            " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
            ("bootstrap", ADMIN, action, "account", str(account_id), "allow", now()))

    return AccountRepo(db, Principal(actor="bootstrap", role=ADMIN)).by_id(account_id)


def bootstrap_from_env(db: Database, env: dict[str, str] | None = None) -> Account | None:
    """Run bootstrap_admin from environment variables, if both are set.

    Returns None when there is nothing to do -- no variables, or an admin
    already exists -- so a container can call this on every boot.

    NOTHING HERE MAY STOP THE APPLICATION STARTING. This runs inside
    AppState.__init__, so an exception escaping it takes the whole process
    down, and a container that crash-loops is far worse than one running
    without an admin: the second you can fix from the dashboard in a minute,
    the first gives you a restart loop and a stack trace. So every failure is
    caught, reported on stdout where the platform's log will show it, and
    swallowed. A too-short password and an unreachable database look the same
    from here and neither is worth a crash.
    """
    import os
    env = env if env is not None else dict(os.environ)
    email = env.get(BOOTSTRAP_EMAIL_VAR, "").strip()
    password = env.get(BOOTSTRAP_PASSWORD_VAR, "")
    if not email or not password:
        return None
    try:
        return bootstrap_admin(db, email, password)
    except AuthError as exc:
        # The ordinary "an admin already exists" path, on every boot after the
        # first. Not worth a line in the log each time.
        if "already exists" not in str(exc):
            print(f"  ! admin bootstrap skipped: {exc}", flush=True)
        return None
    except Exception as exc:                        # noqa: BLE001 - see docstring
        print(f"  ! admin bootstrap failed ({type(exc).__name__}: {exc}). "
              f"The app is starting without one; fix {BOOTSTRAP_EMAIL_VAR} / "
              f"{BOOTSTRAP_PASSWORD_VAR} and redeploy.", flush=True)
        return None
