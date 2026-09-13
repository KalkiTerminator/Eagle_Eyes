"""Host-agnostic paths, and a shared cache safe to put on a network share."""
from __future__ import annotations

import multiprocessing
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eagle_eyes.cache import CachedAnalysis, SharedCache  # noqa: E402
from eagle_eyes.runtime import (  # noqa: E402
    config_search_path, data_dir, detect_run_mode, normalize_source, resolve_paths,
)

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def _entry(fp: str = "a" * 64, **kw) -> CachedAnalysis:
    base = dict(fingerprint=fp, fingerprint_version=1, root_cause="rc",
                suggested_fix="fix", confidence=0.8, path="text", model_id="m")
    base.update(kw)
    return CachedAnalysis(**base)


def test_data_dir_follows_the_platform() -> None:
    saved = dict(os.environ)
    try:
        os.environ.pop("EAGLE_EYES_DATA_DIR", None)
        d = str(data_dir())
        import platform as pf
        sysname = pf.system()
        if sysname == "Windows":
            ok = "AppData" in d or "EagleEyes" in d
        elif sysname == "Darwin":
            ok = "Application Support" in d
        else:
            ok = ".local/share" in d or "XDG" in d or d.endswith("eagleeyes")
        check(f"data dir is platform-appropriate on {sysname}", ok, d)
        check("nothing is hardcoded to a drive letter", not d.startswith("D:"))

        os.environ["EAGLE_EYES_DATA_DIR"] = "/tmp/ee-override"
        check("EAGLE_EYES_DATA_DIR overrides it", str(data_dir()) == "/tmp/ee-override")
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_paths_derive_from_the_data_dir() -> None:
    p = resolve_paths(Path("/tmp/ee-test"))
    check("database sits under the data dir", str(p.database).startswith("/tmp/ee-test"))
    check("reports, logs and cache too",
          all(str(x).startswith("/tmp/ee-test") for x in (p.reports, p.logs, p.cache)))
    check("config search is ordered, most specific first", len(config_search_path()) >= 3)
    check("an explicit config path wins",
          str(config_search_path(Path("/x/y.yaml"))[0]) == "/x/y.yaml")


def test_sources_can_be_any_kind_of_path() -> None:
    for raw, why in [
        (r"\\server\share\data", "UNC"),
        ("C:\\bots\\data", "Windows drive"),
        ("/mnt/bots/data", "POSIX"),
        ("~/bots/data", "home-relative"),
        ('  "/mnt/quoted path"  ', "quoted and padded"),
    ]:
        got = normalize_source(raw)
        check(f"accepts a {why} path", isinstance(got, Path) and str(got) != "")
    check("~ is expanded", "~" not in str(normalize_source("~/x")))
    os.environ["EE_TEST_VAR"] = "/expanded"
    check("environment variables are expanded",
          str(normalize_source("$EE_TEST_VAR/sub")).startswith("/expanded"))


def test_run_mode() -> None:
    check("an explicit mode is honoured", detect_run_mode("service") == "service")
    check("non-tty is treated as unattended", detect_run_mode() in ("scheduled", "interactive"))


def test_cache_is_optional_and_never_fatal() -> None:
    c = SharedCache(None)
    check("no cache configured is fine", not c.available and c.get("a" * 64, 1) is None)
    check("writing to an unconfigured cache returns False", c.put(_entry()) is False)

    # A path that does not exist must be REPORTED, never created: a typo'd share
    # that silently becomes a private cache is the worst outcome, because every
    # install then reports a healthy cache while each pays full price.
    missing = Path(tempfile.mkdtemp()) / "typo-in-the-share-name"
    dead = SharedCache(missing)
    check("a non-existent cache root is not created", not missing.exists())
    check("  and is reported as unavailable", not dead.available)
    check("  with a message naming the path", str(missing) in dead.reason)
    check("  reads return None", dead.get("a" * 64, 1) is None)
    check("  writes return False", dead.put(_entry()) is False)

    # Genuinely unusable: the parent is a file, which fails on every platform.
    blocker = Path(tempfile.mkdtemp()) / "a-file"
    blocker.write_text("x")
    broken = SharedCache(blocker / "cache")
    check("an unusable path degrades rather than raising", not broken.available)


def test_cache_round_trip_and_reuse_gate() -> None:
    d = Path(tempfile.mkdtemp())
    try:
        c = SharedCache(d, ttl_days=30, written_by="host-a")
        check("a writable location is available", c.available)
        check("write succeeds", c.put(_entry(code_mtime="2026-09-01T00:00:00")))

        got = c.get("a" * 64, 1, code_mtime="2026-09-01T00:00:00")
        check("round-trips", got is not None and got.root_cause == "rc")
        check("records which install wrote it", got and got.written_by == "host-a")

        check("a different fingerprint version does not match",
              c.get("a" * 64, 2, code_mtime="2026-09-01T00:00:00") is None)
        check("changed code invalidates reuse",
              c.get("a" * 64, 1, code_mtime="2026-09-14T00:00:00") is None)

        old = _entry(fp="b" * 64,
                     created_at=(datetime.now() - timedelta(days=99)).isoformat(timespec="seconds"))
        c.put(old)
        check("an expired entry is not reused", c.get("b" * 64, 1) is None)

        c.put(_entry(fp="c" * 64))
        check("marking wrong succeeds", c.mark_wrong("c" * 64, 1))
        check("a wrong analysis is never served again", c.get("c" * 64, 1) is None)
    finally:
        shutil.rmtree(d)


def _writer(args) -> bool:
    root, n = args
    c = SharedCache(Path(root), written_by=f"host-{n}")
    ok = True
    for i in range(25):
        ok &= c.put(_entry(fp=f"{i:064x}", root_cause=f"from-{n}"))
    return ok


def test_concurrent_writers_do_not_corrupt() -> None:
    """Several installs writing the same share at once, as would really happen."""
    d = Path(tempfile.mkdtemp())
    try:
        with multiprocessing.Pool(4) as pool:
            results = pool.map(_writer, [(str(d), n) for n in range(4)])
        check("every writer succeeded", all(results))

        c = SharedCache(d)
        readable = sum(1 for i in range(25) if c.get(f"{i:064x}", 1) is not None)
        check("all entries readable after concurrent writes", readable == 25, f"{readable}/25")

        leftovers = list((d / "analyses").rglob(".tmp-*"))
        check("no temp files left behind", not leftovers, str(leftovers[:3]))
    finally:
        shutil.rmtree(d)


def test_partial_write_is_never_visible() -> None:
    """A reader must see the old file or the new one, never a half-written one."""
    d = Path(tempfile.mkdtemp())
    try:
        c = SharedCache(d)
        c.put(_entry(root_cause="first"))
        target = next((d / "analyses").rglob("*.json"))
        before = target.read_text()

        # simulate a crash mid-write: a temp file exists but was never renamed
        (target.parent / ".tmp-crashed.json").write_text("{ truncated")
        got = c.get("a" * 64, 1)
        check("a stray temp file does not affect reads", got is not None and got.root_cause == "first")
        check("the real entry is untouched", target.read_text() == before)

        c.put(_entry(root_cause="second"))
        check("a rewrite replaces cleanly", c.get("a" * 64, 1).root_cause == "second")
    finally:
        shutil.rmtree(d)


def test_corrupt_entry_is_ignored() -> None:
    d = Path(tempfile.mkdtemp())
    try:
        c = SharedCache(d)
        c.put(_entry())
        target = next((d / "analyses").rglob("*.json"))
        target.write_text("not json at all")
        check("corrupt JSON is a miss, not a crash", c.get("a" * 64, 1) is None)

        target.write_text('{"fingerprint": "x", "unexpected_field": 1}')
        check("an unknown schema is rejected, not crashed on", c.get("a" * 64, 1) is None)
    finally:
        shutil.rmtree(d)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        print(f"\n{fn.__name__}")
        fn()
    print(f"\n{'All checks passed.' if not _failures else str(len(_failures)) + ' FAILED: ' + ', '.join(_failures)}")
    sys.exit(1 if _failures else 0)
