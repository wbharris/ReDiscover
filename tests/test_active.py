from rediscover.active import (
    NMAP_TOP_20_PORTS,
    apply_dnsx,
    apply_httpx_jsonl,
    apply_naabu,
    apply_nmap,
    apply_tlsx,
    apply_whatweb_json,
    naabu_argv,
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
    assert host.ports == ["80/tcp"]


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
    assert "dnsx" in names
    assert "httpx" in names or "curl" in names
    assert "naabu" in names
    assert "nmap" in names


def test_apply_dnsx_and_naabu():
    engagement = Engagement(
        domain="example.com",
        hosts=[Host(name="example.com"), Host(name="mail.example.com")],
    )
    apply_dnsx(
        engagement,
        "example.com [A] [93.184.216.34]\nmail.example.com [A] [10.1.2.3]\n",
    )
    apex = engagement.hosts[0]
    mail = engagement.hosts[1]
    assert apex.ips == ["93.184.216.34"]
    assert mail.ips == ["10.1.2.3"]
    assert mail.private is True
    apply_naabu(engagement, "93.184.216.34:443\n10.1.2.3:25\n", engagement.hosts)
    assert apex.ports == ["443/tcp"]
    assert mail.ports == ["25/tcp"]


def test_naabu_uses_nmap_top_20_port_list():
    argv = naabu_argv(["45.33.32.156"])
    assert "-top-ports" not in argv
    assert argv[argv.index("-p") + 1] == NMAP_TOP_20_PORTS
    assert "-no-stdin" in argv
    assert "-duc" in argv
    assert argv[-2:] == ["-host", "45.33.32.156"]
    ports = NMAP_TOP_20_PORTS.split(",")
    assert len(ports) == 20
    assert len(set(ports)) == 20


def test_apply_nmap_keeps_open_ports_only():
    engagement = Engagement(
        domain="scanme.nmap.org",
        hosts=[
            Host(name="scanme.nmap.org", ips=["45.33.32.156"]),
            Host(name="other.nmap.org", ips=["1.2.3.4"]),
        ],
    )
    output = """# Nmap 7.99
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.049s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  tcpwrapped
22/tcp   open  ssh           OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp   filtered http
443/tcp  closed https

Nmap scan report for 1.2.3.4
Host is up.
9/tcp open discard
"""
    apply_nmap(engagement, output, engagement.hosts)
    scanme, other = engagement.hosts
    assert scanme.ports == ["21/tcp", "22/tcp"]
    assert "21/tcp" in scanme.nmap
    assert other.ports == ["9/tcp"]


def test_apply_whatweb_json_ignores_brief_inside_array():
    engagement = Engagement(
        domain="ginandjuice.shop",
        hosts=[Host(name="ginandjuice.shop", technologies=["Amazon ALB"])],
    )
    # WhatWeb 0.6.4 writes the brief line before the closing bracket.
    blob = """[
{"target":"https://ginandjuice.shop","http_status":200,"plugins":{"HTML5":{},"Title":{"string":["Home"]}}}
https://ginandjuice.shop [200 OK] HTML5, Title[Home]
]
"""
    apply_whatweb_json(engagement, blob)
    host = engagement.hosts[0]
    assert host.status == 200
    assert "HTML5" in host.technologies
    assert "Amazon ALB" in host.technologies


def test_apply_tlsx_keeps_in_scope_names():
    engagement = Engagement(domain="example.com", hosts=[Host(name="example.com", source="intake")])
    added = apply_tlsx(
        engagement,
        "\n".join(
            [
                "api.example.com",
                "example.com:443 [www.example.com,cdn.example.net]",
                "*.dev.example.com",
                "notexample.com",
            ]
        ),
    )
    names = {host.name: host for host in engagement.hosts}
    assert added == 2
    assert names["api.example.com"].confirmed is False
    assert names["api.example.com"].source == "tlsx"
    assert "dev.example.com" in names
    assert "cdn.example.net" not in names
    assert "notexample.com" not in names
    assert "tlsx" in names["example.com"].source
