"""Detect and run optional recon binaries."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence

from rediscover.models import ToolRun

DEFAULT_TIMEOUT = 60


def which(name: str) -> str | None:
    return shutil.which(name)


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
