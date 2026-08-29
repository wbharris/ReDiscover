"""Load operator API keys from Discover / theHarvester files (never print values)."""

from __future__ import annotations

import os
from pathlib import Path


def _home() -> Path:
    sudo = os.environ.get("SUDO_USER", "").strip()
    if sudo and sudo != "root":
        return Path("/home") / sudo
    return Path.home()


def github_token() -> str:
    for env in ("GITHUB_TOKEN", "GH_TOKEN"):
        val = (os.environ.get(env) or "").strip()
        if val:
            return val
    path = _home() / ".theHarvester" / "api-keys.yaml"
    if not path.is_file():
        return ""
    return _github_from_yaml_text(path.read_text(encoding="utf-8", errors="replace"))


def _github_from_yaml_text(text: str) -> str:
    in_github = False
    for raw in text.splitlines():
        if raw.startswith("  github:"):
            in_github = True
            continue
        if in_github:
            if raw.startswith("  ") and not raw.startswith("    ") and raw.strip().endswith(":"):
                break
            if "key:" in raw:
                return raw.split("key:", 1)[1].strip().strip("'\"")
    return ""
