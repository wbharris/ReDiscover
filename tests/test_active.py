from rediscover.active import (
    apply_httpx_jsonl,
    parse_resolve,
    probe_targets,
    run_active,
)
from rediscover.models import Engagement, Host, ToolRun
from rediscover.netutil import is_private_ipv4
from rediscover.passive import parse_dnstwist
from rediscover.pipeline import recon


def test_private_ipv4():
    assert is_private_ipv4("10.0.0.1")
    assert is_private_ipv4("192.168.1.8")
    assert is_private_ipv4("127.0.0.1")
    assert not is_private_ipv4("93.184.216.34")
    assert not is_private_ipv4("example.com")


def test_parse_resolve_keeps_public_and_private():
    ips = parse_resolve("93.184.216.34\n10.1.2.3\nnot-an-ip\n")
    assert "93.184.216.34" in ips
    assert "10.1.2.3" in ips


def test_probe_skips_private_hosts():
    engagement = Engagement(
        domain="example.com",
        hosts=[
            Host(name="example.com", ips=["93.184.216.34"]),
            Host(name="int.example.com", ips=["10.0.0.5"], private=True),
        ],
    )
    names = [h.name for h in probe_targets(engagement, 25)]
    assert names == ["example.com"]


def test_apply_httpx_jsonl():
    engagement = Engagement(
        domain="example.com",
        hosts=[Host(name="example.com", source="intake")],
    )
    blob = (
        '{"url":"https://example.com","input":"example.com","title":"Example Domain",'
        '"webserver":"cloudflare","status_code":200,"tech":["Cloudflare"],'
        '"a":["93.184.216.34"]}\n'
    )
    apply_httpx_jsonl(engagement, blob)
    host = engagement.hosts[0]
    assert host.status == 200
    assert host.title == "Example Domain"
    assert host.server == "cloudflare"
    assert "Cloudflare" in host.technologies
    assert "93.184.216.34" in host.ips


def test_parse_dnstwist_json():
    names = parse_dnstwist(
        '[{"domain":"examp1e.com","fuzzer":"homoglyph"},{"domain":"example.com"}]',
        "example.com",
    )
    assert names == ["examp1e.com"]


def test_run_active_with_stub():
    engagement = recon("example.com", offline=True)
    engagement.mode = "active"
    engagement.improve = []
    engagement.assumptions = []

    def runner(name: str, argv: list[str]) -> ToolRun:
        if name.startswith("resolve:"):
            return ToolRun(name=name, status="ran", command=argv, output="93.184.216.34\n")
        if name == "httpx":
            return ToolRun(
                name=name,
                status="ran",
                command=argv,
                output=(
                    '{"url":"https://example.com","input":"example.com",'
                    '"title":"Example Domain","status_code":200,"webserver":"ecs",'
                    '"tech":[],"a":["93.184.216.34"]}\n'
                ),
            )
        if name == "nmap":
            return ToolRun(
                name=name,
                status="ran",
                command=argv,
                output="Nmap scan report for 93.184.216.34\n80/tcp open http\n",
            )
        return ToolRun(name=name, status="skipped", command=argv, reason="stub")

    run_active(engagement, runner, nmap=True, max_hosts=5)
    host = next(h for h in engagement.hosts if h.name == "example.com")
    assert host.status == 200
    assert host.title == "Example Domain"
    assert "80/tcp" in host.nmap


def test_recon_nmap_requires_active():
    try:
        recon("example.com", offline=True, nmap=True)
    except ValueError as exc:
        assert "--nmap requires --active" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_dry_run_active_plans_http():
    engagement = recon("example.com", dry_run=True, active=True, nmap=True)
    names = [t.name for t in engagement.tools]
    assert "whois" in names
    assert "httpx" in names or "curl" in names
    assert "nmap" in names
