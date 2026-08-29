"""Detect and run optional recon binaries."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from rediscover.models import ToolRun

DEFAULT_TIMEOUT = 60

_EXTRA_BIN_DIRS = (
    Path.home() / "go" / "bin",
    Path("/root/go/bin"),
    Path("/usr/local/go/bin"),
    Path("/usr/local/bin"),
    Path.home() / "theHarvester" / ".venv" / "bin",
)

# Kali also ships a Python httpx CLI at /usr/bin/httpx. ReDiscover wants
# ProjectDiscovery's ELF binary (typically /usr/local/bin/httpx).
_PREFER_ELF = frozenset({"httpx"})


def is_elf(path: str | Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def _candidates(name: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    folders: list[Path] = []
    for part in os.environ.get("PATH", "").split(os.pathsep):
        if part:
            folders.append(Path(part))
    folders.extend(_EXTRA_BIN_DIRS)
    path_hit = shutil.which(name)
    if path_hit:
        folders.insert(0, Path(path_hit).parent)
    for folder in folders:
        candidate = folder / name
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        try:
            key = str(candidate.resolve())
        except OSError:
            key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def which(name: str) -> str | None:
    found = _candidates(name)
    if name in _PREFER_ELF:
        for path in found:
            if is_elf(path):
                return path
    return found[0] if found else None


def run(
    name: str,
    argv: Sequence[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolRun:
    binary = argv[0] if argv else ""
    path = which(binary)
    if path is None:
        return ToolRun(
            name=name,
            status="skipped",
            command=list(argv),
            reason=f"{binary} not installed",
        )
    cmd = [path, *list(argv)[1:]]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolRun(
            name=name,
            status="failed",
            command=cmd,
            reason=f"timed out after {timeout}s",
        )
    except OSError as exc:
        return ToolRun(
            name=name,
            status="failed",
            command=cmd,
            reason=str(exc),
        )
    text = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    if proc.returncode != 0 and not (proc.stdout or "").strip():
        return ToolRun(
            name=name,
            status="failed",
            command=cmd,
            reason=f"exit {proc.returncode}",
            output=text.strip(),
        )
    return ToolRun(
        name=name,
        status="ran",
        command=cmd,
        output=(proc.stdout or "").strip(),
        reason="" if proc.returncode == 0 else f"exit {proc.returncode}",
    )


def planned(name: str, argv: Sequence[str]) -> ToolRun:
    binary = argv[0] if argv else ""
    path = which(binary)
    if path is None:
        return ToolRun(
            name=name,
            status="skipped",
            command=list(argv),
            reason=f"{binary} not installed",
        )
    return ToolRun(name=name, status="planned", command=[path, *list(argv)[1:]])


def spawn(name: str, argv: Sequence[str]) -> ToolRun:
    """Start a GUI/browser and do not wait for it to exit."""
    binary = argv[0] if argv else ""
    path = which(binary)
    if path is None:
        return ToolRun(
            name=name,
            status="skipped",
            command=list(argv),
            reason=f"{binary} not installed",
        )
    cmd = [path, *list(argv)[1:]]
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return ToolRun(name=name, status="failed", command=cmd, reason=str(exc))
    return ToolRun(name=name, status="ran", command=cmd, reason="spawned")
