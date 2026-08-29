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
    assert "7. Confidence" in md


def test_dry_run_plans_tools():
    engagement = recon("example.com", dry_run=True)
    names = [t.name for t in engagement.tools]
    assert "whois" in names
    assert "dns-a" in names
    assert "subfinder" in names
    assert all(t.status in {"planned", "skipped"} for t in engagement.tools)
