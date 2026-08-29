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
)


def which(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for folder in _EXTRA_BIN_DIRS:
        candidate = folder / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


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
