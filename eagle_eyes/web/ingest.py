"""Turning an uploaded folder into the same thing the scanner produces.

A browser cannot hand a server a directory, only files -- so the page sends
each file with its relative path, the server rebuilds the tree, and
`discovery.discover` runs over it. That is deliberate: the service line and bot
number come from the DIRECTORY NAMES rather than from log content, which is
attacker-influenced; each screenshot is matched by the capture line in its own
log; and two screenshots seconds apart still pair to neither.

The alternative -- parsing an upload directly -- would be a second set of
pairing rules to keep in step with the scanner's, and nothing would notice them
diverging. tests/test_tabs.py uploads the fixture estate and asserts both paths
produce identical candidates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timezone

from ..discovery import EXC_RE, decode_text, failure_time

# Generous enough for a long run's log, small enough that a single request
# cannot exhaust a container's memory.
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_CODE_BYTES = 4 * 1024 * 1024
MAX_IMAGE_BYTES = 10 * 1024 * 1024

# Checked against the leading bytes, not the filename or the declared type --
# both of which the uploader controls. An image that is not one of these is
# refused rather than forwarded to a model as an opaque blob.
IMAGE_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
}
WEBP_PREFIX, WEBP_TAG = b"RIFF", b"WEBP"

_NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$")


class IngestError(ValueError):
    """A refusal to accept an upload, with a reason the submitter can act on."""


def discover_upload(root: Path) -> tuple[list, str, str]:
    """Run the CLI's discovery over a rebuilt upload tree.

    This is the point of accepting a folder rather than a file. `discover()`
    is the same function the scanner uses against a real share: it reads the
    service line and bot number FROM THE PATH rather than from log content
    (which is attacker-influenced), finds each screenshot by the capture line
    in its own log, and refuses to pair when two sit within seconds of the
    failure. A web upload that re-implemented any of that would be a second
    set of rules to keep in step with the first.

    Returns (candidates, share_root, code_root) with the roots as display
    strings, or an empty list when the tree holds nothing recognisable.
    """
    from ..discovery import discover

    share_root = _find_share_root(root)
    if share_root is None:
        return [], "", ""
    code_root = _find_code_root(root) or share_root

    candidates = discover(share_root, share_root, code_root)
    return (candidates,
            str(share_root.relative_to(root)) or ".",
            str(code_root.relative_to(root)) or ".")


def _find_share_root(root: Path) -> Path | None:
    """The directory holding `data/`, which is what parse_location expects.

    A browser sends the dropped folder's own name as the first path component,
    so the tree is `<root>/<whatever they called it>/data/...` -- and people
    drop the share, or one service line, or one bot. Finding `data/` and taking
    its parent handles all of those without asking them to name it.
    """
    if (root / "data").is_dir():
        return root
    best = None
    for path in root.rglob("data"):
        if path.is_dir() and (best is None or len(path.parts) < len(best.parts)):
            best = path
    return best.parent if best else None


def _find_code_root(root: Path) -> Path | None:
    for name in ("code_folder", "code", "source"):
        if (root / name).is_dir():
            return root / name
        for path in root.rglob(name):
            if path.is_dir():
                return path
    return None


def sniff_image(raw: bytes) -> str:
    """The image's actual type from its leading bytes, or '' if it is not one."""
    for magic, mime in IMAGE_MAGIC.items():
        if raw.startswith(magic):
            return mime
    if raw[:4] == WEBP_PREFIX and raw[8:12] == WEBP_TAG:
        return "image/webp"
    return ""
