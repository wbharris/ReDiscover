from rediscover.cli import main
from rediscover.enrich import parse_crtsh, parse_github_search, parse_homepage, run_enrich
from rediscover.keys import _github_from_yaml_text
from rediscover.pipeline import recon


def test_parse_crtsh_filters_other_domains():
    body = """[
      {"name_value": "www.example.com\\nmail.example.com"},
      {"name_value": "notexample.com"},
      {"common_name": "*.api.example.com"}
    ]"""
    names = parse_crtsh(body, "example.com")
    assert "www.example.com" in names or "example.com" in names or "mail.example.com" in names
    assert "api.example.com" in names
    assert "notexample.com" not in names


def test_parse_homepage_mailto_and_hosts():
    html = """
    <a href="mailto:ops@example.com">mail</a>
    <a href="https://status.example.com/">status</a>
    <a href="https://evil.example.net/">no</a>
    """
    hosts, emails = parse_homepage(html, "example.com", "https://example.com/")
    assert "ops@example.com" in emails
    assert "status.example.com" in hosts
    assert "evil.example.net" not in hosts


def test_parse_github_search():
    body = '{"items":[{"html_url":"https://github.com/acme/www.example.com-config"}]}'
    hosts, _emails = parse_github_search(body, "example.com")
    assert "www.example.com" in hosts or any(h.endswith("example.com") for h in hosts)


def test_github_yaml_parser():
    text = "apikeys:\n  bevigil:\n    key:\n  github:\n    key: ghp_testtoken\n  hunter:\n    key: x\n"
    assert _github_from_yaml_text(text) == "ghp_testtoken"


def test_run_enrich_stub_fetcher():
    engagement = recon("example.com", offline=True)

    def fetch(url, headers=None, timeout=25):
        if "crt.sh" in url:
            return 200, '[{"name_value": "dev.example.com"}]', ""
        if "api.github.com" in url:
            return 200, '{"items":[]}', ""
        if "example.com" in url:
            return 200, '<a href="mailto:sec@example.com">x</a>', ""
        return 404, "", "no"

    run_enrich(engagement, fetcher=fetch)
    names = {h.name for h in engagement.hosts}
    assert "dev.example.com" in names
    assert any(not h.confirmed for h in engagement.hosts if h.name == "dev.example.com")
    assert any(c.value == "sec@example.com" for c in engagement.contacts)
    assert any(t.name == "crt.sh" and t.status == "ran" for t in engagement.tools)


def test_cli_enrich_dry_via_recon(capsys):
    assert main(["recon", "example.com", "--dry-run", "--enrich"]) == 0
    out = capsys.readouterr().out
    assert "crt.sh" in out
