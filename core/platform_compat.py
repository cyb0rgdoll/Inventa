"""Small cross-platform helpers for CLI execution."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def python_executable() -> str:
    """Return the current Python interpreter for child Python tools."""
    return sys.executable or shutil.which("python3") or shutil.which("python") or "python"


def is_windows() -> bool:
    return os.name == "nt"


def is_wsl() -> bool:
    try:
        return "microsoft" in platform.uname().release.lower()
    except Exception:
        return False


def clear_screen() -> None:
    os.system("cls" if is_windows() else "clear")


def open_path(path: Path) -> bool:
    """Open a path in the native file browser when the platform supports it."""
    path = Path(path)
    try:
        if is_windows():
            os.startfile(str(path))  # type: ignore[attr-defined]
            return True
        if is_wsl() and shutil.which("explorer.exe") and shutil.which("wslpath"):
            win_path = subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
            subprocess.Popen(["explorer.exe", win_path])
            return True
        if sys.platform == "darwin" and shutil.which("open"):
            subprocess.Popen(["open", str(path)])
            return True
        if shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", str(path)])
            return True
    except Exception:
        return False
    return False


def raw_socket_prefix(binary: str) -> Optional[List[str]]:
    """Return a command prefix for tools requiring raw-socket privileges."""
    if is_windows():
        return [binary]
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return [binary]
    if shutil.which("sudo"):
        return ["sudo", "-n", binary]
    return None
