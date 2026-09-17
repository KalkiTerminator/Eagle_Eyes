"""Turning an upload into the same thing the scanner produces.

An upload is a strictly worse input than a share path, and the whole design
here is about saying so rather than quietly filling the gaps in.

What the scanner gets from the filesystem and an upload does not have:

  * A SIBLING DIRECTORY. The scanner pairs a screenshot by reading the capture
    line out of the log and finding that file next to it, and refuses to pair
    when two candidates sit within seconds of the failure (ARCHITECTURE 4.4).
    An upload has neither -- the image is whatever the person attached. That is
    recorded as pairing_method='uploaded', its own value, because calling it
    'log_path' would claim the log named it.

  * A CODE MTIME. The reuse gate (DATA_MODEL 2.6) uses the code file's mtime as
    a pseudo-version: an analysis is reused only when the code has not changed
    since. Pasted code has no mtime, so the gate cannot tell. It therefore
    refuses reuse rather than assuming -- serving a fix for a version of the
    code that no longer exists is worse than paying for another analysis.

  * A TREE LOCATION. service_line/bot_number come from the share path, never
    from log content, precisely because log content is attacker-influenced.
    An upload has no path, so the submitter names the bot and that is recorded
    as their claim, not as a fact derived from the estate.
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


@dataclass
class Upload:
    """One submitted failure, and an honest account of what came with it."""
    service_line: str
    bot_number: str
    log_text: str
    code_text: str = ""
    code_name: str = ""
    image: bytes | None = None
    image_type: str = ""
    submitted_by: str = ""

    exception_type: str = ""
    message: str = ""
    occurred_at: datetime | None = None

    # What is missing, in the submitter's words, shown on the report.
    degradations: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.service_line}/{self.bot_number}"

    @property
    def pairing_method(self) -> str:
        return "uploaded" if self.image else "none"

    @property
    def may_reuse(self) -> bool:
        """Always False for an upload. See the module docstring."""
        return False

    @property
    def code_mtime(self) -> None:
        """There isn't one, and there is no honest substitute.

        Using the upload time would make every submission look like freshly
        changed code and defeat reuse in a way that reads like a bug rather
        than a decision. Using a fixed value would make stale code look
        current. None is the true answer, and the reuse gate is built to
        refuse on it.
        """
        return None


def build_upload(*, service_line: str, bot_number: str, log_bytes: bytes,
                 code_bytes: bytes = b"", code_name: str = "",
                 image_bytes: bytes = b"", submitted_by: str = "") -> Upload:
    """Validate and parse an upload, or raise IngestError saying why not."""
    service_line = _name(service_line, "service line")
    bot_number = _name(bot_number, "bot number")

    if not log_bytes:
        raise IngestError("a log file is required -- it is the only input that "
                          "cannot be substituted for.")
    _size("log", log_bytes, MAX_LOG_BYTES)
    _size("code", code_bytes, MAX_CODE_BYTES)
    _size("screenshot", image_bytes, MAX_IMAGE_BYTES)

    log_text = decode_text(log_bytes)
    code_text = decode_text(code_bytes) if code_bytes else ""

    image_type = ""
    if image_bytes:
        image_type = sniff_image(image_bytes)
        if not image_type:
            raise IngestError(
                "that screenshot is not a PNG, JPEG, GIF or WebP. The file's "
                "own leading bytes are what is checked, not its name or the "
                "type the browser declared -- both of which the uploader "
                "chooses.")

    up = Upload(service_line=service_line, bot_number=bot_number,
                log_text=log_text, code_text=code_text,
                code_name=code_name[:120], image=image_bytes or None,
                image_type=image_type, submitted_by=submitted_by)

    if (m := EXC_RE.search(log_text)):
        innermost = m.group(1).split(" ---> ")[-1]
        exc, _, msg = innermost.partition(":")
        up.exception_type = exc.strip()
        up.message = " ".join(msg.split())[:300]
    up.occurred_at = failure_time(log_text) or datetime.now(timezone.utc)

    up.degradations = _degradations(up)
    return up


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


def _degradations(up: Upload) -> list[str]:
    """Exactly what this input cannot support, in the report's own words.

    The CLI degrades the same way against a share; the difference is that an
    upload degrades on almost every axis at once, so saying nothing would let a
    reader assume the diagnosis rests on more than it does.
    """
    out = []
    if not up.code_text:
        out.append(
            "No source was submitted, so the diagnosis rests on the log alone. "
            "It can name what failed; it cannot point at the line.")
    else:
        out.append(
            "The source was pasted rather than read from the code folder, so "
            "there is no modification time to check it against. A previous "
            "analysis of this same failure will NOT be reused -- serving a fix "
            "for code that has since changed is worse than paying again.")
    if up.image:
        out.append(
            "The screenshot is whatever was attached to this submission. "
            "Unlike a scanned failure, nothing cross-checks it against the "
            "log's own capture line, so it is recorded as 'uploaded' rather "
            "than as a verified pairing.")
    if not up.exception_type:
        out.append(
            "No exception could be found in this log. Check that the right "
            "file was submitted -- a diagnosis without one is guesswork.")
    return out


def sniff_image(raw: bytes) -> str:
    """The image's actual type from its leading bytes, or '' if it is not one."""
    for magic, mime in IMAGE_MAGIC.items():
        if raw.startswith(magic):
            return mime
    if raw[:4] == WEBP_PREFIX and raw[8:12] == WEBP_TAG:
        return "image/webp"
    return ""


def _name(value: str, what: str) -> str:
    value = (value or "").strip()
    if not value:
        raise IngestError(f"a {what} is required")
    if not _NAME_OK.match(value):
        raise IngestError(
            f"that {what} contains characters that are not allowed. Use "
            "letters, digits, spaces, dots, hyphens and underscores.")
    return value


def _size(what: str, raw: bytes, cap: int) -> None:
    if len(raw) > cap:
        raise IngestError(
            f"that {what} is {len(raw) // (1024 * 1024)}MB; the limit is "
            f"{cap // (1024 * 1024)}MB.")
