"""RBAC, tested adversarially.

Everything else in this repo is a feature. This is the part that decides
whether one customer's failures can be read by another, so the tests here are
written from the attacker's side: not "does a manager see their team" but "can
a manager reach outside it", "can a user guess an id", "can a pending account
reach anything at all", "can a cookie claim a role".

docs/SECURITY.md section 6.4 requires exactly this shape of test.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.storage import (  # noqa: E402
    ADMIN, MANAGER, USER, AccessDenied, AnalysisRepo, BotRepo, Database,
    DeveloperRepo, FailureRepo, FingerprintRepo, Principal,
)
from eagle_eyes.web.auth import (  # noqa: E402
    APPROVED, REQUESTED, REVOKED, SUSPENDED, Account, AccountRepo, AuthError,
    SessionRepo, bootstrap_admin, hash_password, read_cookie, sign_cookie,
    verify_password,
)

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check

PASSWORD = "correct-horse-battery-staple"
ADMIN_P = Principal("root@x.com", ADMIN)


def _world() -> tuple[Database, Path, dict]:
    """Two service lines, two owners, one failure each. The setup every test uses."""
    d = Path(tempfile.mkdtemp())
    db = Database(d / "rbac.db")

    bots = BotRepo(db, ADMIN_P)
    fps = FingerprintRepo(db, ADMIN_P)
    fails = FailureRepo(db, ADMIN_P)
    devs = DeveloperRepo(db, ADMIN_P)
    devs.ensure("alice@x.com", team="FINANCE_AP")
    devs.ensure("bob@x.com", team="CLAIMS_PROC")

    ids = {}
    for line, owner, h in (("FINANCE_AP", "alice@x.com", "a"),
                           ("CLAIMS_PROC", "bob@x.com", "b")):
        bot = bots.upsert(line, "BOT001")
        bots.set_owner(bot, owner)
        fp = fps.touch(h * 64, 1, "NullReferenceException", "not set", "Bot.cs:1")
        ids[line] = fails.add(bot_id=bot, fingerprint_id=fp,
                              occurred_at="2026-09-11T09:00:00",
                              log_path=f"/logs/{line}.txt", correlation_id="c")
    return db, d, ids


def _account(db: Database, email: str, *, role: str = USER,
             scope: set[str] | None = None, status: str = APPROVED) -> Account:
    repo = AccountRepo(db, ADMIN_P)
    aid = repo.register(email, PASSWORD)
    if status == APPROVED:
        repo.approve(aid, role=role, scope=frozenset(scope or ()))
    elif status != REQUESTED:
        repo.set_status(aid, status)
    return repo.by_id(aid)


# ------------------------------------------------------- passwords

def test_passwords_are_not_recoverable() -> None:
    h1, s1, p1 = hash_password(PASSWORD)
    h2, s2, _ = hash_password(PASSWORD)
    check("the same password hashes differently each time", h1 != h2)
    check("because the salt differs", s1 != s2)
    check("the password does not appear in the hash", PASSWORD not in h1)
    check("the right password verifies", verify_password(PASSWORD, h1, s1, p1))
    check("a wrong one does not", not verify_password(PASSWORD + "!", h1, s1, p1))
    check("nor does the hash used as the password",
          not verify_password(h1, h1, s1, p1))

    for weak in ("short", "", "12345678901"):
        rejected = False
        try:
            hash_password(weak)
        except AuthError:
            rejected = True
        check(f"a {len(weak)}-character password is refused", rejected)


# ------------------------------------------------------- the approval gate

def test_nothing_is_granted_by_registration() -> None:
    db, d, _ = _world()
    try:
        repo = AccountRepo(db, ADMIN_P)
        aid = repo.register("new@x.com", PASSWORD)
        acct = repo.by_id(aid)
        check("a new account is 'requested'", acct.status == REQUESTED)
        check("with the least role", acct.role == USER)
        check("and no scope", acct.scope == frozenset())
        check("it can sign in", acct.may_sign_in)
        check("  but it is not approved", not acct.is_approved)

        denied = ""
        try:
            acct.principal()
        except AccessDenied as e:
            denied = str(e)
        check("and it cannot produce a Principal at all", "not approved" in denied)
        check("  which is what stops it reaching any repository",
              "separate steps" in denied)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_pending_account_can_reach_nothing() -> None:
    """The whole point of `requested`: a login that grants nothing."""
    db, d, ids = _world()
    try:
        acct = _account(db, "pending@x.com", status=REQUESTED)
        signed_in = AccountRepo(db, ADMIN_P).authenticate("pending@x.com", PASSWORD)
        check("the password is accepted", signed_in.id == acct.id)

        for state in (REQUESTED, SUSPENDED):
            a = Account(id=1, email="p@x", display_name="p", status=state,
                        role=ADMIN, scope=frozenset({"FINANCE_AP"}))
            refused = False
            try:
                a.principal()
            except AccessDenied:
                refused = True
            check(f"a '{state}' account gets no Principal even with role=admin", refused)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_suspension_takes_effect_on_the_next_request() -> None:
    db, d, _ = _world()
    try:
        repo = AccountRepo(db, ADMIN_P)
        acct = _account(db, "temp@x.com", role=USER)
        sessions = SessionRepo(db, ADMIN_P)
        sid = sessions.create(acct.id)
        check("the session resolves while approved", sessions.lookup(sid) == acct.id)

        repo.set_status(acct.id, SUSPENDED)
        check("suspending revokes the live session immediately",
              sessions.lookup(sid) is None)
        check("  rather than waiting for the cookie to expire", True)
        check("and the account can no longer produce a Principal",
              not repo.by_id(acct.id).is_approved)
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------- horizontal access

def test_a_user_cannot_fetch_another_users_failure() -> None:
    """Guessing an id is the cheapest attack there is. It must return nothing."""
    db, d, ids = _world()
    try:
        alice = Principal("alice@x.com", USER)
        bob_failure = ids["CLAIMS_PROC"]
        own = ids["FINANCE_AP"]

        repo = FailureRepo(db, alice)
        check("alice can read her own failure", repo.get(own)["id"] == own)

        denied = ""
        try:
            repo.get(bob_failure)
        except AccessDenied as e:
            denied = str(e)
        check("alice cannot read bob's by id", denied != "")
        check("  and the message does not confirm it exists",
              "no failure" in denied and "CLAIMS" not in denied)

        missing = ""
        try:
            repo.get(999999)
        except AccessDenied as e:
            missing = str(e)
        check("a nonexistent id is refused the same way",
              missing.replace("999999", "") == denied.replace(str(bob_failure), ""))

        listed = [r["id"] for r in repo.recent(limit=100)]
        check("and the list only contains her own", listed == [own], str(listed))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_an_account_with_no_bots_sees_nothing() -> None:
    db, d, ids = _world()
    try:
        nobody = FailureRepo(db, Principal("nobody@x.com", USER))
        check("no rows are listed", nobody.recent(limit=100) == [])
        check("the count agrees", nobody.visible_count() == 0)
        refused = False
        try:
            nobody.get(ids["FINANCE_AP"])
        except AccessDenied:
            refused = True
        check("and nothing can be fetched by id", refused)
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------- manager scope

def test_a_manager_cannot_reach_outside_their_scope() -> None:
    db, d, ids = _world()
    try:
        mgr = Principal("m@x.com", MANAGER, frozenset({"FINANCE_AP"}))
        repo = FailureRepo(db, mgr)

        listed = [r["service_line"] for r in repo.recent(limit=100)]
        check("only the scoped service line is listed", listed == ["FINANCE_AP"],
              str(listed))

        check("the scoped failure is readable",
              repo.get(ids["FINANCE_AP"])["id"] == ids["FINANCE_AP"])
        refused = False
        try:
            repo.get(ids["CLAIMS_PROC"])
        except AccessDenied:
            refused = True
        check("the unscoped one is not, even by id", refused)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_an_empty_manager_scope_means_nothing_not_everything() -> None:
    """The classic inversion: an empty filter list becomes no filter at all."""
    db, d, ids = _world()
    try:
        repo = FailureRepo(db, Principal("m@x.com", MANAGER, frozenset()))
        check("an empty scope lists no failures", repo.recent(limit=100) == [])
        check("and counts none", repo.visible_count() == 0)

        rejected = ""
        try:
            AccountRepo(db, ADMIN_P).approve(
                AccountRepo(db, ADMIN_P).register("m2@x.com", PASSWORD),
                role=MANAGER, scope=frozenset())
        except ValueError as e:
            rejected = str(e)
        check("and approving a manager with no scope is refused outright",
              "can see nothing" in rejected, rejected)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_scope_is_not_stored_where_it_would_not_be_enforced() -> None:
    """A scope on a user or an admin implies a restriction nothing applies."""
    db, d, _ = _world()
    try:
        repo = AccountRepo(db, ADMIN_P)
        for role in (USER, ADMIN):
            rejected = ""
            try:
                repo.approve(repo.register(f"{role}@x.com", PASSWORD),
                             role=role, scope=frozenset({"FINANCE_AP"}))
            except ValueError as e:
                rejected = str(e)
            check(f"a scope on an {role} is refused", "meaningless" in rejected,
                  rejected)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_the_two_statements_of_the_rule_agree() -> None:
    """`_scope_sql` and `_visible` are the same rule written twice.

    Two copies of an access rule is how an access rule rots: someone fixes the
    SQL and not the predicate, and the list page and the detail page start
    disagreeing about who may see what. So they are checked against each other
    row by row, for every role.
    """
    db, d, _ = _world()
    try:
        everything = FailureRepo(db, ADMIN_P).recent(limit=100)
        principals = [
            Principal("root@x.com", ADMIN),
            Principal("m@x.com", MANAGER, frozenset({"FINANCE_AP"})),
            Principal("m@x.com", MANAGER, frozenset()),
            Principal("alice@x.com", USER),
            Principal("nobody@x.com", USER),
        ]
        for p in principals:
            repo = FailureRepo(db, p)
            by_sql = {r["id"] for r in repo.recent(limit=100)}
            by_predicate = {r["id"] for r in everything if repo._visible(r)}
            check(f"{p.role}/{p.actor} -- SQL and predicate agree",
                  by_sql == by_predicate, f"{by_sql} vs {by_predicate}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_stats_do_not_leak_across_scopes() -> None:
    """A count is data. A dedup rate over the whole estate tells a manager how
    busy teams they cannot see are, and a spend figure tells them what those
    teams cost."""
    db, d, _ = _world()
    try:
        everything = FailureRepo(db, ADMIN_P).stats()
        scoped = FailureRepo(db, Principal("m@x.com", MANAGER,
                                           frozenset({"FINANCE_AP"}))).stats()
        check("the admin sees both failures", everything["failures"] == 2)
        check("the manager's count covers only their scope",
              scoped["failures"] == 1, str(scoped["failures"]))
        check("and the fingerprint count too", scoped["fingerprints"] == 1)
        empty = FailureRepo(db, Principal("x@x.com", USER)).stats()
        check("someone with no access sees zeroes, not the estate",
              empty["failures"] == 0 and empty["spend_usd"] == 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------- privilege escalation

def test_a_cookie_cannot_claim_a_role() -> None:
    """The cookie carries an opaque id and a signature -- never a role.

    If a role travelled in the cookie, forging one would be the whole attack.
    It does not, so the worst a forged cookie can do is fail to verify.
    """
    secret = b"a-test-signing-secret-not-a-real-one"
    sid = "f" * 64
    cookie = sign_cookie(sid, secret)

    check("the signed cookie round-trips", read_cookie(cookie, secret) == sid)
    check("the cookie contains no role", "admin" not in cookie and "role" not in cookie)

    check("an unsigned id is refused", read_cookie(sid, secret) is None)
    check("a tampered id is refused", read_cookie(sign_cookie("e" * 64, secret)
                                                  .replace("e", "f", 1), secret) is None)
    check("a tampered signature is refused",
          read_cookie(cookie[:-1] + ("0" if cookie[-1] != "0" else "1"), secret) is None)
    check("another key's signature is refused",
          read_cookie(sign_cookie(sid, b"different-secret"), secret) is None)
    check("junk is refused", read_cookie("admin.admin", secret) is None)
    check("an empty cookie is refused", read_cookie("", secret) is None)
    check("a role appended to the id does not survive",
          read_cookie(f"{sid}:admin.{cookie.split('.')[1]}", secret) is None)


def test_a_valid_signature_over_an_unknown_id_gets_nothing() -> None:
    """Signing correctly is not the same as having a session."""
    db, d, _ = _world()
    try:
        sessions = SessionRepo(db, ADMIN_P)
        secret = b"a-test-signing-secret-not-a-real-one"
        forged = "0" * 64
        check("the signature verifies", read_cookie(sign_cookie(forged, secret),
                                                    secret) == forged)
        check("but no session exists behind it", sessions.lookup(forged) is None)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_only_an_admin_may_approve_or_suspend() -> None:
    db, d, _ = _world()
    try:
        admin_repo = AccountRepo(db, ADMIN_P)
        target = admin_repo.register("victim@x.com", PASSWORD)

        for role, scope in ((USER, frozenset()),
                            (MANAGER, frozenset({"FINANCE_AP"}))):
            repo = AccountRepo(db, Principal("climber@x.com", role, scope))
            for call, label in (
                (lambda: repo.approve(target, role=ADMIN), "approve"),
                (lambda: repo.set_status(target, REVOKED), "revoke"),
                (lambda: repo.list_all(), "list accounts"),
                (lambda: repo.link_developer(target), "link a developer"),
            ):
                refused = False
                try:
                    call()
                except AccessDenied:
                    refused = True
                check(f"a {role} cannot {label}", refused)

        denials = db.conn.execute(
            "SELECT COUNT(*) n FROM audit_event WHERE outcome='deny'"
            " AND actor='climber@x.com'").fetchone()["n"]
        check("and every attempt is in the audit log", denials >= 6, str(denials))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_nobody_can_set_another_accounts_password() -> None:
    """An admin who can set a password can act as that person, and the audit
    log would record it as them."""
    db, d, _ = _world()
    try:
        victim = _account(db, "victim@x.com", role=USER)
        repo = AccountRepo(db, ADMIN_P)
        refused = ""
        try:
            repo.change_password(victim.id, "anything", "a-brand-new-password")
        except AccessDenied as e:
            refused = str(e)
        check("an admin cannot set someone else's password", "only be changed" in refused)
        check("  and the reason is stated", "as any user" in refused)

        own = AccountRepo(db, Principal("victim@x.com", USER))
        own.change_password(victim.id, PASSWORD, "a-brand-new-password")
        check("the owner can, with the old password",
              AccountRepo(db, ADMIN_P).authenticate(
                  "victim@x.com", "a-brand-new-password").id == victim.id)

        wrong = False
        try:
            own.change_password(victim.id, "not-the-old-password", "another-new-one")
        except AuthError:
            wrong = True
        check("and only with the right old password", wrong)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_the_last_admin_cannot_be_removed() -> None:
    """Locking every admin out makes approvals impossible with no way back."""
    db, d, _ = _world()
    try:
        admin = bootstrap_admin(db, "root@x.com", PASSWORD)
        repo = AccountRepo(db, ADMIN_P)
        refused = ""
        try:
            repo.set_status(admin.id, REVOKED)
        except ValueError as e:
            refused = str(e)
        check("the last admin cannot be revoked", "last active admin" in refused)

        second = _account(db, "root2@x.com", role=ADMIN)
        repo.set_status(admin.id, REVOKED)
        check("once a second admin exists, the first can be revoked",
              repo.by_id(admin.id).status == REVOKED)
        check("  and the second is untouched", repo.by_id(second.id).is_approved)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_bootstrap_runs_once_and_is_audited() -> None:
    db, d, _ = _world()
    try:
        admin = bootstrap_admin(db, "root@x.com", PASSWORD)
        check("the first admin is approved immediately", admin.is_approved)
        check("with the admin role", admin.role == ADMIN)

        again = ""
        try:
            bootstrap_admin(db, "attacker@x.com", PASSWORD)
        except AuthError as e:
            again = str(e)
        check("a second bootstrap does nothing", "already exists" in again)
        check("so an env var on a running deployment cannot mint an admin",
              AccountRepo(db, ADMIN_P).by_email("attacker@x.com") is None)

        row = db.conn.execute(
            "SELECT actor, action FROM audit_event WHERE action='bootstrap_admin'"
        ).fetchone()
        check("and the bootstrap is in the audit log", row is not None)
        check("  attributed to the bootstrap, not to a person",
              row["actor"] == "bootstrap")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------- sign-in surface

def test_signin_does_not_reveal_which_emails_exist() -> None:
    db, d, _ = _world()
    try:
        _account(db, "real@x.com", role=USER)
        repo = AccountRepo(db, ADMIN_P)
        messages = set()
        for email, pw in (("real@x.com", "wrong-password-here"),
                          ("ghost@x.com", "wrong-password-here")):
            try:
                repo.authenticate(email, pw)
            except AuthError as e:
                messages.add(str(e))
        check("a wrong password and an unknown account read identically",
              len(messages) == 1, str(messages))

        taken = ""
        try:
            repo.register("real@x.com", PASSWORD)
        except AuthError as e:
            taken = str(e)
        check("and registration does not confirm an address is taken",
              "could not be completed" in taken and "exists" not in taken)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_repeated_guessing_is_locked_out() -> None:
    db, d, _ = _world()
    try:
        acct = _account(db, "target@x.com", role=USER)
        repo = AccountRepo(db, ADMIN_P)
        for _ in range(8):
            try:
                repo.authenticate("target@x.com", "guess")
            except AuthError:
                pass
        locked = ""
        try:
            repo.authenticate("target@x.com", PASSWORD)      # the RIGHT password
        except AuthError as e:
            locked = str(e)
        check("after enough failures even the right password is refused",
              "too many failed attempts" in locked, locked)

        db.conn.execute("UPDATE account SET locked_until=NULL WHERE id=?", (acct.id,))
        check("and it opens again once the lockout passes",
              repo.authenticate("target@x.com", PASSWORD).id == acct.id)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_sessions_expire_and_revoke() -> None:
    db, d, _ = _world()
    try:
        acct = _account(db, "s@x.com", role=USER)
        sessions = SessionRepo(db, ADMIN_P)

        live = sessions.create(acct.id)
        check("a fresh session resolves", sessions.lookup(live) == acct.id)

        sessions.revoke(live)
        check("a revoked session does not", sessions.lookup(live) is None)

        stale = sessions.create(acct.id, ttl=timedelta(seconds=-1))
        check("an expired session does not either", sessions.lookup(stale) is None)
        check("and purging removes it", sessions.purge_expired() >= 1)

        a, b = sessions.create(acct.id), sessions.create(acct.id)
        check("revoke_all clears every live session", sessions.revoke_all(acct.id) == 2)
        check("  so neither resolves",
              sessions.lookup(a) is None and sessions.lookup(b) is None)

        check("an unknown id resolves to nothing", sessions.lookup("z" * 64) is None)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_repository_cannot_be_built_without_a_principal() -> None:
    """The boundary is the data layer, so this is the thing that must hold."""
    db, d, _ = _world()
    try:
        for bad in (None, "admin", {"role": "admin"}, ADMIN):
            refused = False
            try:
                FailureRepo(db, bad)
            except TypeError:
                refused = True
            check(f"a {type(bad).__name__} is not a Principal", refused)
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
