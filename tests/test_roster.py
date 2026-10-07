from rediscover.models import ToolRun
from rediscover.passive import collect_hosts, scoped_urls
from rediscover.pipeline import recon
from rediscover.roster import ROSTER, chaos_key
from rediscover.tools import which


def test_roster_is_recon_only():
    names = {tool.name for tool in ROSTER}
    assert "nuclei" not in names
    assert "ffuf" not in names
    assert "sqlmap" not in names
    for tool in ROSTER:
        assert tool.when in {"always", "full", "active", "ports"}


def test_collect_hosts_accepts_fast_tools_and_drops_wildcards():
    runs = [
        ToolRun(
            name="assetfinder",
            status="ran",
            output="*.example.com\nhttps://api.example.com/a\napi.example.com\n",
        ),
        ToolRun(
            name="findomain",
            status="ran",
            output="api.example.com\nnotexample.com\n",
        ),
        ToolRun(
            name="gau",
            status="ran",
            output="https://api.example.com/a\n",
        ),
    ]
    names = [host.name for host in collect_hosts("example.com", runs)]
    assert names == ["api.example.com", "example.com"]
    api = next(host for host in collect_hosts("example.com", runs) if host.name == "api.example.com")
    assert "assetfinder" in api.source
    assert "findomain" in api.source
    assert "gau" not in api.source


def test_scoped_urls_keep_in_scope_http():
    blob = "\n".join(
        [
            "https://api.example.com/a",
            "https://evil.com/example.com",
            "http://www.example.com/b",
            "ftp://example.com/c",
            "https://notexample.com/",
            "https://example.com.evil.com/x",
        ]
    )
    assert scoped_urls(blob, "example.com", limit=10) == [
        "https://api.example.com/a",
        "http://www.example.com/b",
    ]


def test_scoped_urls_cap():
    blob = "\n".join(f"https://example.com/{i}" for i in range(20))
    assert len(scoped_urls(blob, "example.com", limit=3)) == 3


def test_chaos_without_key_is_skipped(monkeypatch):
    monkeypatch.delenv("CHAOS_KEY", raising=False)
    monkeypatch.delenv("PDCP_API_KEY", raising=False)
    assert chaos_key() == ""
    engagement = recon("example.com", dry_run=True)
    chaos = next(tool for tool in engagement.tools if tool.name == "chaos")
    assert chaos.status == "skipped"
    if which("chaos"):
        assert "API key" in chaos.reason
    else:
        assert "not installed" in chaos.reason
