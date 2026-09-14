"""Where things live, on whatever machine this is running on.

The analyzer is an ordinary application. It runs on a desktop, a laptop, a VM,
a build agent or a server; on Windows, Linux or macOS; installed, or portable
from a folder. Nothing in the design assumes a particular host.

That means no path is ever hardcoded. Data goes where the platform says user
data goes, config is searched in a documented order, and every location can be
overridden. A build that only works on one machine is a build that will be
rewritten the first time someone else needs it.

Sources are equally unconstrained: a local folder, a mapped drive, a UNC path,
a mounted NFS export, a synced folder. They are all just paths.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "EagleEyes"
PORTABLE_MARKER = "portable.txt"


def is_frozen() -> bool:
    """True when packaged (PyInstaller and friends)."""
    return getattr(sys, "frozen", False)


def install_dir() -> Path:
    """The folder the application itself lives in."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def is_portable() -> bool:
    """Portable mode: keep everything beside the application.

    For a USB stick, a locked-down desktop with no per-user profile worth
    writing to, or anywhere an install is not wanted. Enabled by dropping a
    file named `portable.txt` next to the application.
    """
    try:
        return (install_dir() / PORTABLE_MARKER).is_file()
    except OSError:
        return False


def data_dir() -> Path:
    """Where this install keeps its database, logs and reports.

    Order: EAGLE_EYES_DATA_DIR, then portable mode, then the platform default.
    """
    if (env := os.environ.get("EAGLE_EYES_DATA_DIR")):
        return Path(env).expanduser()
    if is_portable():
        return install_dir() / "data"

    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        return Path(base or Path.home() / "AppData" / "Local") / APP_NAME
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_DATA_HOME")
    return (Path(base) if base else Path.home() / ".local" / "share") / APP_NAME.lower()


def in_container() -> bool:
    """Whether this process is running inside a container.

    Checked so the data directory can warn rather than silently write to a
    filesystem that disappears on the next deploy.
    """
    if os.environ.get("EAGLE_EYES_IN_CONTAINER", "").strip().lower() in (
            "1", "true", "yes"):
        return True
    if Path("/.dockerenv").exists():
        return True
    try:
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(marker in cgroup for marker in ("docker", "kubepods", "containerd"))


def ephemeral_storage_warning() -> str | None:
    """A warning when data would land somewhere a redeploy wipes, else None.

    In a container `data_dir()` resolves to ~/.local/share/eagleeyes -- inside
    the image layer, which is recreated on every deploy. Everything would work:
    accounts could be created, failures analysed, money spent, and all of it
    would vanish at the next push with no error anywhere. A volume mounted and
    pointed at by EAGLE_EYES_DATA_DIR is the fix; saying so loudly is this
    function's whole job.
    """
    if not in_container():
        return None
    configured = os.environ.get("EAGLE_EYES_DATA_DIR", "").strip()
    if not configured:
        return (f"Running in a container with no EAGLE_EYES_DATA_DIR set, so data "
                f"goes to {data_dir()} -- inside the image layer, which is "
                f"recreated on every deploy. Accounts, analyses and spend history "
                f"will be silently lost. Attach a volume and point "
                f"EAGLE_EYES_DATA_DIR at it.")
    path = Path(configured).expanduser()
    if not path.is_absolute():
        return (f"EAGLE_EYES_DATA_DIR is '{configured}', a relative path. It "
                f"resolves against whatever the working directory happens to be, "
                f"which in a container is not somewhere a volume is mounted. Use "
                f"an absolute path.")
    return None


def config_dir() -> Path:
    if (env := os.environ.get("EAGLE_EYES_CONFIG_DIR")):
        return Path(env).expanduser()
    if is_portable():
        return install_dir() / "config"

    system = platform.system()
    if system == "Windows":
        base = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA")
        return Path(base or Path.home() / "AppData" / "Roaming") / APP_NAME
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / APP_NAME.lower()


def config_search_path(explicit: Path | None = None) -> list[Path]:
    """Config locations, most specific first. First hit wins.

    A per-machine override beats a shared default, so one config can sit on a
    network path for everyone while any machine can still differ.
    """
    out: list[Path] = []
    if explicit:
        out.append(Path(explicit).expanduser())
    if (env := os.environ.get("EAGLE_EYES_CONFIG")):
        out.append(Path(env).expanduser())
    out.append(Path.cwd() / "eagle_eyes.yaml")
    out.append(config_dir() / "config.yaml")
    out.append(install_dir() / "config" / "config.yaml")
    return out


def find_config(explicit: Path | None = None) -> Path | None:
    for p in config_search_path(explicit):
        if p.is_file():
            return p
    return None


@dataclass(frozen=True)
class Paths:
    data: Path
    database: Path
    reports: Path
    logs: Path
    cache: Path

    def ensure(self) -> "Paths":
        for p in (self.data, self.reports, self.logs, self.cache):
            p.mkdir(parents=True, exist_ok=True)
        return self


def resolve_paths(data_override: Path | None = None) -> Paths:
    base = Path(data_override).expanduser() if data_override else data_dir()
    return Paths(
        data=base,
        database=base / "eagle_eyes.db",
        reports=base / "reports",
        logs=base / "logs",
        cache=base / "cache",
    )


# ---------------------------------------------------------------------------
# How this instance is being run
# ---------------------------------------------------------------------------

INTERACTIVE = "interactive"
SCHEDULED = "scheduled"
SERVICE = "service"


def detect_run_mode(explicit: str | None = None) -> str:
    """Interactive, scheduled, or service.

    Declared in config where it matters; inferred otherwise. The distinction is
    real: interactive can prompt, the other two must never block waiting for a
    human who is not there.
    """
    if explicit:
        return explicit
    if not sys.stdin or not sys.stdin.isatty():
        return SCHEDULED
    return INTERACTIVE


def can_prompt() -> bool:
    """Whether asking the user a question can possibly be answered."""
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except Exception:
        return False


def gui_possible() -> bool:
    """Whether a window can be opened here.

    Present on a desktop or laptop, over RDP, and in a VM with a session.
    Absent on a headless server, in CI, and over a plain SSH connection.
    """
    try:
        import tkinter  # noqa: F401
    except Exception:
        return False
    if platform.system() in ("Windows", "Darwin"):
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def describe_host() -> dict[str, str]:
    """For the run header, a report footer, and bug reports."""
    return {
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "machine": platform.node(),
        "frozen": str(is_frozen()),
        "portable": str(is_portable()),
        "run_mode": detect_run_mode(),
        "gui": str(gui_possible()),
        "data_dir": str(data_dir()),
    }


# ---------------------------------------------------------------------------
# Path handling that has to survive every host
# ---------------------------------------------------------------------------

def normalize_source(raw: str | Path) -> Path:
    """Accept whatever the user gives: UNC, mapped drive, POSIX, ~, env vars.

    All four of these are just paths, and the application should not care which
    kind it was handed:
        \\\\server\\share\\data        C:\\bots\\data
        /mnt/bots/data              ~/bots/data
    """
    text = os.path.expandvars(str(raw)).strip().strip('"')
    return Path(text).expanduser()


def is_network_path(p: Path) -> bool:
    """UNC, or a drive letter that is not local. Best-effort, never fatal."""
    s = str(p)
    if s.startswith("\\\\") or s.startswith("//"):
        return True
    if platform.system() == "Windows" and len(s) > 1 and s[1] == ":":
        try:
            import ctypes
            # 4 == DRIVE_REMOTE
            return ctypes.windll.kernel32.GetDriveTypeW(f"{s[0]}:\\") == 4
        except Exception:
            return False
    return False
