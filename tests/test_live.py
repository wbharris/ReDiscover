"""Optional live checks against the IANA documentation domain example.com."""

from __future__ import annotations

import os

import pytest

from rediscover.models import ToolRun
from rediscover.pipeline import recon
from rediscover.tools import run as real_run

pytestmark = pytest.mark.skipif(
    os.environ.get("REDISCOVER_LIVE") != "1",
    reason="set REDISCOVER_LIVE=1 to probe example.com",
)

_PASSIVE_LIVE = {"whois"}
_ACTIVE_LIVE = {"httpx", "curl", "whatweb"}


def _runner(name: str, argv: list[str]) -> ToolRun:
    if name in _PASSIVE_LIVE or name.startswith("dns-"):
        return real_run(name, argv, timeout=25)
    if name in _ACTIVE_LIVE or name.startswith("resolve:") or name.startswith("curl:"):
        return real_run(name, argv, timeout=45)
    return ToolRun(name=name, status="skipped", command=argv, reason="live-smoke")


def test_live_passive_example_com():
    engagement = recon("example.com", quick=True, runner=_runner)
    assert engagement.domain == "example.com"
    assert any(t.name == "whois" and t.status == "ran" for t in engagement.tools)
    assert any(t.name.startswith("dns-") and t.status == "ran" for t in engagement.tools)
    assert engagement.hosts[0].name == "example.com"


def test_live_active_example_com():
    engagement = recon(
        "example.com",
        offline=True,
        active=True,
        max_hosts=1,
        runner=_runner,
    )
    assert engagement.mode == "active"
    apex = next(h for h in engagement.hosts if h.name == "example.com")
    assert apex.status in {200, 301, 302, 303, 307, 308}
    assert apex.url.startswith("http")
