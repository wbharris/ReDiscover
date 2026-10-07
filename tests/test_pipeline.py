from rediscover.models import ToolRun
from rediscover.passive import collect_hosts, parse_whois, validate_domain
from rediscover.pipeline import recon
from rediscover.report import to_markdown


def test_validate_domain_strips_url():
    assert validate_domain("https://WWW.Example.COM/path") == "example.com"


def test_validate_domain_rejects_garbage():
    try:
        validate_domain("not a domain")
    except ValueError as exc:
        assert "not a domain" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_parse_whois_filters_privacy_email():
    raw = """
Registrar: Example Registrar
Organization: Example Inc
Name Server: ns1.example.com
Registrant Email: admin@example.com
Registrar Abuse Contact Email: abuse@example.com
WHOIS Privacy Email: proxy@identity-protect.org
"""
    registrar, org, nses, emails = parse_whois(raw)
    assert registrar == "Example Registrar"
    assert org == "Example Inc"
    assert nses == ["ns1.example.com"]
    assert emails == ["admin@example.com"]


def test_collect_hosts_merges_subdomain_tools():
    domain = "example.com"
    runs = [
        ToolRun(
            name="subfinder",
            status="ran",
            output="www.example.com\nmail.example.com\n",
        ),
        ToolRun(
            name="amass",
            status="ran",
            output="mail.example.com\n",
        ),
        ToolRun(name="whois", status="ran", output="ignored"),
    ]
    hosts = collect_hosts(domain, runs)
    names = [h.name for h in hosts]
    assert names == ["example.com", "mail.example.com"]
    mail = next(h for h in hosts if h.name == "mail.example.com")
    assert "subfinder" in mail.source
    assert "amass" in mail.source


def test_collect_hosts_rejects_suffix_collision():
    runs = [
        ToolRun(
            name="subfinder",
            status="ran",
            output="notexample.com\napi.example.com\n",
        )
    ]
    names = [h.name for h in collect_hosts("example.com", runs)]
    assert names == ["api.example.com", "example.com"]


def test_offline_case():
    engagement = recon("example.com", company="Example Inc", offline=True)
    assert engagement.domain == "example.com"
    assert engagement.company == "Example Inc"
    assert engagement.mode == "offline"
    assert engagement.hosts[0].name == "example.com"
    assert engagement.tools == []
    md = to_markdown(engagement)
    assert "example.com" in md
    assert "--offline" in md
    assert "9. Confidence" in md


def test_dry_run_plans_tools():
    engagement = recon("example.com", dry_run=True)
    names = [t.name for t in engagement.tools]
    assert "whois" in names
    assert "dns-a" in names
    assert "subfinder" in names
    assert "dnstwist" in names
    assert "crt.sh" in names
    assert "urlfinder" in names
    assert "tlsx" in names
    assert "httpx" in names or "curl" in names
    assert "nmap" in names
    subfinder = next(tool for tool in engagement.tools if tool.name == "subfinder")
    assert "-all" in subfinder.command
    assert "-duc" in subfinder.command
    assert subfinder.command[subfinder.command.index("-max-time") + 1] == "2"
    assert all(t.status in {"planned", "skipped"} for t in engagement.tools)


def test_passive_skips_probes():
    names = [t.name for t in recon("example.com", dry_run=True, passive=True).tools]
    assert "subfinder" in names
    assert "crt.sh" in names
    assert "nmap" not in names
    assert "httpx" not in names
    assert "naabu" not in names
    assert "tlsx" not in names
    assert "urlfinder" in names


def test_no_ports_keeps_http():
    engagement = recon("example.com", dry_run=True, nmap=False)
    names = [t.name for t in engagement.tools]
    assert "httpx" in names or "curl" in names
    assert "nmap" not in names
    assert "naabu" not in names


def test_quick_skips_heavy_tools():
    names = [t.name for t in recon("example.com", dry_run=True, quick=True).tools]
    assert "subfinder" in names
    assert "assetfinder" in names
    assert "findomain" in names
    assert "amass" not in names
    assert "dnstwist" not in names
    assert "chaos" not in names
    assert "gau" not in names
    assert "waybackurls" not in names
    assert "urlfinder" not in names
    quick = recon("example.com", dry_run=True, quick=True)
    subfinder = next(tool for tool in quick.tools if tool.name == "subfinder")
    assert "-all" not in subfinder.command
    assert "-duc" in subfinder.command
    assert subfinder.command[subfinder.command.index("-max-time") + 1] == "1"
    assert "theHarvester" in names
    assert "crt.sh" in names
    assert "nmap" in names


def test_enrich_names_join_the_probe_list():
    from rediscover.models import ToolRun

    def runner(name: str, argv: list[str]) -> ToolRun:
        if name == "httpx":
            assert "dev.example.com" in argv
            return ToolRun(
                name=name,
                status="ran",
                command=argv,
                output=(
                    '{"url":"https://dev.example.com","input":"dev.example.com",'
                    '"status_code":200,"title":"Dev","webserver":"stub","tech":[]}\n'
                ),
            )
        if name.startswith("resolve:"):
            return ToolRun(name=name, status="ran", command=argv, output="93.184.216.34\n")
        return ToolRun(name=name, status="skipped", command=argv, reason="stub")

    def fetch(url, headers=None, timeout=25):
        if "crt.sh" in url:
            return 200, '[{"name_value": "dev.example.com"}]', ""
        return 404, "", "no"

    engagement = recon(
        "example.com",
        quick=True,
        nmap=False,
        max_hosts=5,
        runner=runner,
        fetch=fetch,
    )
    dev = next(host for host in engagement.hosts if host.name == "dev.example.com")
    assert "crt.sh" in dev.source
    assert dev.status == 200
    assert dev.confirmed is False
    assert not any("Probe new enrich hosts" in item.question for item in engagement.improve)


def test_full_plan_includes_roster():
    names = [t.name for t in recon("example.com", dry_run=True).tools]
    for name in ("assetfinder", "findomain", "amass", "chaos", "gau", "waybackurls", "urlfinder", "tlsx", "nmap"):
        assert name in names
    assert "nuclei" not in names
