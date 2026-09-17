"""Rebuilding an uploaded folder on disk, safely.

A browser folder picker hands over each file with a RELATIVE PATH the client
chose -- `webkitRelativePath`. Writing those paths under a directory is the
whole feature and also, taken literally, a path traversal hole: a client that
sends `../../../../etc/cron.d/x` is asking us to write outside the directory,
and nothing about the upload looks unusual while it does it.

So every component is checked rather than cleaned. Cleaning invites the
half-fixed version -- strip `..` and `....//` still gets through. This refuses
the whole upload and names the path, because a folder containing a hostile path
is not a folder anyone meant to analyse.

What is refused:

    absolute paths             /etc/passwd, \\\\server\\share\\x
    drive letters and streams  C:\\Windows\\x, C:x, x:$DATA
    parent traversal           any `..` component, before or after separators
    NUL and control bytes      truncation tricks against the layer below
    reserved Windows names     CON, PRN, AUX, NUL, COM1-9, LPT1-9
    absurd depth or length     a tree nobody produced by hand

And after all of that the resolved path is compared against the root again,
because a symlink in a directory we created ourselves is the one case the
component checks cannot see.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_FILES = 2000
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_DEPTH = 24
MAX_COMPONENT = 200
MAX_PATH = 1024

# Windows reserved device names, with or without an extension. Creating one of
# these on Windows does not make a file; it opens a device.
_RESERVED = re.compile(
    r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)", re.IGNORECASE)

# Anything that is not a printable character we would expect in a file name.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class UnsafePath(ValueError):
    """A path in the upload that will not be written. Names the path."""


@dataclass
class Rebuilt:
    root: Path
    files: list[Path] = field(default_factory=list)
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)


def safe_relative(raw: str) -> PurePosixPath:
    """Validate one client-supplied relative path, or raise UnsafePath.

    Returns it normalised to POSIX separators. Does not touch the filesystem --
    `write_tree` does the containment check that needs a real root.
    """
    if not raw or not raw.strip():
        raise UnsafePath("an upload contained a file with no name")
    if len(raw) > MAX_PATH:
        raise UnsafePath(f"path is longer than {MAX_PATH} characters")
    if _CONTROL.search(raw):
        raise UnsafePath(f"path contains a control character: {raw!r}")

    # Treat both separators as separators regardless of the server's platform.
    # A backslash is a literal character in a POSIX filename, so a Windows
    # client's path would otherwise arrive as one very odd component.
    unified = raw.replace("\\", "/")

    if unified.startswith("/"):
        raise UnsafePath(f"absolute path refused: {raw!r}")
    # C:, C:/, and the NTFS stream form x:$DATA all carry a colon in the first
    # component; no ordinary relative path does.
    first = unified.split("/", 1)[0]
    if ":" in first:
        raise UnsafePath(f"drive or stream reference refused: {raw!r}")

    parts = [p for p in unified.split("/") if p not in ("", ".")]
    if not parts:
        raise UnsafePath(f"path names no file: {raw!r}")
    if len(parts) > MAX_DEPTH:
        raise UnsafePath(f"path is more than {MAX_DEPTH} directories deep: {raw!r}")

    for part in parts:
        if part == "..":
            raise UnsafePath(f"parent traversal refused: {raw!r}")
        if len(part) > MAX_COMPONENT:
            raise UnsafePath(f"a path component is too long: {raw!r}")
        if _RESERVED.match(part):
            raise UnsafePath(f"reserved device name refused: {raw!r}")
        if part.endswith((" ", ".")) and part not in (".", ".."):
            # Windows silently strips these, so two different uploaded paths
            # can collide into one file.
            raise UnsafePath(f"path component ends with a space or dot: {raw!r}")

    return PurePosixPath(*parts)


def write_tree(root: Path, items: list[tuple[str, bytes]]) -> Rebuilt:
    """Write (relative_path, content) pairs under `root`.

    Raises UnsafePath on the first path that is not safe -- the upload is
    rejected whole rather than partially accepted, because a folder with one
    hostile path in it is not something anyone assembled by accident.
    """
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    out = Rebuilt(root=root)

    if len(items) > MAX_FILES:
        raise UnsafePath(
            f"{len(items)} files in that folder; the limit is {MAX_FILES}. "
            "Pick a single bot or date rather than the whole share.")

    for raw, content in items:
        relative = safe_relative(raw)

        if len(content) > MAX_FILE_BYTES:
            out.skipped.append(f"{raw} ({len(content) // (1024 * 1024)}MB, too large)")
            continue
        if out.total_bytes + len(content) > MAX_TOTAL_BYTES:
            raise UnsafePath(
                f"that folder is over {MAX_TOTAL_BYTES // (1024 * 1024)}MB in total. "
                "Pick a narrower part of the tree.")

        target = (root / Path(*relative.parts))

        # The check the component rules cannot do: resolve and confirm we are
        # still inside. Covers a symlink planted by an earlier file in the same
        # upload, and any platform normalisation we did not anticipate.
        resolved_parent = _resolve_within(target.parent, root, raw)
        resolved_parent.mkdir(parents=True, exist_ok=True)
        final = resolved_parent / target.name
        _resolve_within(final, root, raw)

        if final.is_symlink():
            raise UnsafePath(f"upload would write through a symlink: {raw!r}")
        final.write_bytes(content)
        out.files.append(final)
        out.total_bytes += len(content)

    return out


def _resolve_within(path: Path, root: Path, raw: str) -> Path:
    """Resolve `path` and confirm it is inside `root`, or raise."""
    resolved = Path(os.path.realpath(path))
    try:
        resolved.relative_to(root)
    except ValueError:
        raise UnsafePath(f"path escapes the upload directory: {raw!r}") from None
    return resolved
