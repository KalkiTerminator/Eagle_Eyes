"""The model boundary and the secret rules, enforced rather than trusted.

docs/ARCHITECTURE.md requires that the model integration sit behind one module
so the provider can be swapped without touching anything else. A rule like that
decays silently unless something fails the build when it is broken.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "eagle_eyes" / "model_gateway.py"

SDK_MODULES = {"anthropic", "boto3", "botocore"}
# Real key shapes. The test files deliberately contain a fake one, so the
# scan skips anything already marked as such.
SECRET_PATTERNS = [
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "Anthropic API key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"aws_secret_access_key\s*=\s*['\"][^'\"]{20,}"), "AWS secret key"),
]

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


def test_only_the_gateway_imports_an_sdk() -> None:
    offenders = []
    for py in sorted((ROOT / "eagle_eyes").rglob("*.py")):
        if py == GATEWAY:
            continue
        hit = _imports(py) & SDK_MODULES
        if hit:
            offenders.append(f"{py.relative_to(ROOT)} imports {', '.join(sorted(hit))}")
    check("no module outside model_gateway imports a provider SDK",
          not offenders, "; ".join(offenders))

    check("the gateway itself does import one",
          bool(_imports(GATEWAY) & SDK_MODULES) or "anthropic" in GATEWAY.read_text(),
          "imports are inside functions, which is fine")


def test_both_backends_exist_and_are_reachable() -> None:
    src = GATEWAY.read_text(encoding="utf-8")
    for cls in ("BedrockBackend", "ByokBackend", "MockBackend"):
        check(f"{cls} is defined", f"class {cls}" in src)
    for kind in ("bedrock", "byok", "mock"):
        check(f"create_backend handles '{kind}'", f'"{kind}"' in src)


def test_no_secret_material_in_the_repo() -> None:
    skip_dirs = {".git", "sandbox", "__pycache__", ".venv"}
    hits = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(p in skip_dirs for p in path.parts):
            continue
        if path.suffix.lower() in {".png", ".jpg", ".pyc", ".db"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern, label in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                line = text[:m.start()].count("\n") + 1
                context = text.splitlines()[line - 1] if line <= len(text.splitlines()) else ""
                # Test fixtures legitimately contain credential-SHAPED strings.
                # They must say so on the same line, so that an unmarked one is
                # always a finding rather than something the scanner guesses at.
                if any(marker in context for marker in
                       ("FAKE_KEY", "REDACTED", "not a real key", "not real keys")):
                    continue
                hits.append(f"{path.relative_to(ROOT)}:{line} {label}")
    check("no credential material committed", not hits, "; ".join(hits))


def test_gitignore_covers_the_obvious() -> None:
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pat in ("sandbox/", "*.db", "config/local.yaml"):
        check(f".gitignore covers {pat}", pat in gi)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        print(f"\n{fn.__name__}")
        fn()
    print(f"\n{'All checks passed.' if not _failures else str(len(_failures)) + ' FAILED: ' + ', '.join(_failures)}")
    sys.exit(1 if _failures else 0)
