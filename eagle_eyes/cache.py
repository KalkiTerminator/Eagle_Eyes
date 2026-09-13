"""A dedup cache that can be shared between installs on a network path.

The problem this solves
-----------------------
The analyzer runs wherever it is installed, and each install keeps its own
SQLite database. That is right for local state, but wrong for dedup: ten
laptops means ten caches, so the same failure is analysed ten times. Measured
against docs/COST_MODEL.md, spreading 2,000 failures/day across ten installs
takes the effective hit rate from 70% to roughly 7%, and the bill from about
$16.63/day to $51.55.

Why not just put the database on the share
------------------------------------------
SQLite over SMB is a known way to corrupt a database. Its locking depends on
byte-range locks that network filesystems implement inconsistently or not at
all, and the failure is silent until it is catastrophic. Not worth it.

What this does instead
----------------------
One small JSON file per fingerprint, in a sharded directory. Reads are plain
file reads with no locking. Writes go to a temporary file in the same directory
and are then renamed into place -- `os.replace` is atomic on NTFS and on POSIX,
so a reader sees either the old file or the new one, never a half-written one.
Two installs writing the same fingerprint concurrently is harmless: the content
is a function of the fingerprint, so last-writer-wins loses nothing.

It is always optional. An unreachable share, a laptop offline, a path that does
not exist -- any of these degrade to "no cache", which costs money and breaks
nothing. A dedup cache that can take the application down is a bad trade.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

SCHEMA_VERSION = 1


@dataclass
class CachedAnalysis:
    fingerprint: str
    fingerprint_version: int
    root_cause: str
    suggested_fix: str
    confidence: float
    path: str                       # template | text | vision | fallback
    model_id: str
    code_mtime: str | None = None   # pseudo-version; see ARCHITECTURE 4.5
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    marked_wrong: bool = False
    schema_version: int = SCHEMA_VERSION
    written_by: str = ""            # which install wrote it, for troubleshooting


class SharedCache:
    """Reads and writes never raise. Failures are reported, not propagated."""

    def __init__(self, root: Path | None, *, ttl_days: int = 30, written_by: str = "") -> None:
        self.root = Path(root) if root else None
        self.ttl = timedelta(days=ttl_days)
        self.written_by = written_by
        self.available = False
        self.reason = "not configured"
        self.stats = {"hit": 0, "miss": 0, "stale": 0, "rejected": 0, "write_ok": 0, "write_fail": 0}
        if self.root:
            self._probe()

    def _probe(self) -> None:
        """Check once at startup, so a dead share is reported rather than discovered.

        The configured root must ALREADY EXIST. A shared cache is something an
        administrator sets up; the application uses it and does not invent it.

        This matters more than it looks. With `mkdir(parents=True)`, a typo'd
        share path -- `\\fileserver\eagle-eyes-cahce` -- would be created and
        become a private cache that shares with nobody. Every install would
        report a healthy cache while each quietly paid full price, which is
        exactly the silent cost increase docs/COST_MODEL.md 9 warns about.
        Failing loudly on a path that does not exist is the whole point.
        """
        try:
            if not self.root.is_dir():
                self.available = False
                self.reason = (f"{self.root} does not exist - not creating it. "
                               f"Check the path, or ask for the share to be set up.")
                return
            (self.root / "analyses").mkdir(exist_ok=True)
            probe = self.root / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            self.available = True
            self.reason = "ready"
        except OSError as exc:
            self.available = False
            self.reason = f"unavailable ({exc.__class__.__name__}) - continuing without it"

    def _path_for(self, fingerprint: str, version: int) -> Path:
        # Shard so a directory never holds tens of thousands of entries, which
        # some network filesystems enumerate very slowly.
        return self.root / "analyses" / fingerprint[:2] / f"{fingerprint}.v{version}.json"

    def get(self, fingerprint: str, version: int, *,
            code_mtime: str | None = None) -> CachedAnalysis | None:
        """Return a reusable analysis, or None. Never raises.

        Applies the reuse gate from docs/DATA_MODEL.md 2.6: same fingerprint
        version, inside the TTL, code unchanged, and not marked wrong.
        """
        if not self.available:
            return None
        p = self._path_for(fingerprint, version)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.stats["miss"] += 1
            return None

        try:
            entry = CachedAnalysis(**raw)
        except TypeError:
            self.stats["rejected"] += 1       # written by a newer schema
            return None

        if entry.schema_version != SCHEMA_VERSION:
            self.stats["rejected"] += 1
            return None
        if entry.marked_wrong:
            self.stats["rejected"] += 1
            return None
        try:
            if datetime.now() - datetime.fromisoformat(entry.created_at) > self.ttl:
                self.stats["stale"] += 1
                return None
        except ValueError:
            self.stats["rejected"] += 1
            return None
        if code_mtime is not None and entry.code_mtime != code_mtime:
            self.stats["stale"] += 1          # code changed: the old fix may mislead
            return None

        self.stats["hit"] += 1
        return entry

    def put(self, entry: CachedAnalysis) -> bool:
        """Write atomically. Returns success; never raises."""
        if not self.available:
            return False
        entry.written_by = entry.written_by or self.written_by
        p = self._path_for(entry.fingerprint, entry.fingerprint_version)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            # Temp file in the SAME directory, so the rename is a rename and
            # not a cross-device copy (which would not be atomic).
            fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".tmp-", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(asdict(entry), fh, indent=1, sort_keys=True)
                os.replace(tmp, p)            # atomic on NTFS and POSIX
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
            self.stats["write_ok"] += 1
            return True
        except OSError:
            self.stats["write_fail"] += 1
            return False

    def mark_wrong(self, fingerprint: str, version: int) -> bool:
        """Developer feedback invalidates reuse for everyone, immediately."""
        entry = None
        if self.available:
            p = self._path_for(fingerprint, version)
            try:
                entry = CachedAnalysis(**json.loads(p.read_text(encoding="utf-8")))
            except (OSError, ValueError, TypeError):
                return False
        if entry is None:
            return False
        entry.marked_wrong = True
        return self.put(entry)

    def summary(self) -> str:
        if not self.available:
            return f"shared cache: {self.reason}"
        s = self.stats
        looked = s["hit"] + s["miss"] + s["stale"] + s["rejected"]
        rate = f"{s['hit'] / looked:.0%}" if looked else "n/a"
        return (f"shared cache: {s['hit']} hits / {looked} lookups ({rate}), "
                f"{s['write_ok']} written"
                + (f", {s['write_fail']} write failures" if s["write_fail"] else ""))
