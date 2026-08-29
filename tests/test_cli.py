from pathlib import Path

from rediscover.cli import main
from rediscover.models import ToolRun
from rediscover.passive import run_passive
from rediscover.pipeline import recon


def test_cli_offline_stdout(capsys):
    assert main(["recon", "example.com", "--offline"]) == 0
    out = capsys.readouterr().out
    assert "# ReDiscover™ — example.com" in out
    assert "`offline`" in out


def test_cli_rejects_bad_domain(capsys):
    assert main(["recon", "nope", "--offline"]) == 2
    err = capsys.readouterr().err
    assert "not a domain" in err


def test_cli_nmap_requires_active(capsys):
    assert main(["recon", "example.com", "--offline", "--nmap"]) == 2
    err = capsys.readouterr().err
    assert "--nmap requires --active" in err


def test_cli_dry_run_active(capsys):
    assert main(["recon", "example.com", "--dry-run", "--active"]) == 0
    out = capsys.readouterr().out
    assert "`dry-run`" in out
    assert "httpx" in out or "curl" in out


def test_cli_json_and_output(tmp_path: Path):
    dest = tmp_path / "case.json"
    assert main(["recon", "example.com", "--offline", "--json", "-o", str(dest)]) == 0
    text = dest.read_text(encoding="utf-8")
    assert '"domain": "example.com"' in text


def test_cli_version(capsys):
    try:
        main(["-V"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("version should SystemExit")
    out = capsys.readouterr().out
    assert "ReDiscover™" in out


def test_run_passive_with_stub_runner():
    engagement = recon("example.com", company="Hold", offline=True)
    engagement.mode = "passive"
    engagement.tools = []
    engagement.improve = []
    engagement.assumptions = []

    def runner(name: str, argv: list[str]) -> ToolRun:
        if name == "whois":
            return ToolRun(
                name="whois",
                status="ran",
                command=argv,
                output="Registrar: Example Registrar\nOrganization: Stub Org\nadmin@example.com\n",
            )
        if name == "dns-a":
            return ToolRun(name=name, status="ran", command=argv, output="93.184.216.34\n")
        if name == "subfinder":
            return ToolRun(name=name, status="ran", command=argv, output="www.example.com\napi.example.com\n")
        return ToolRun(name=name, status="skipped", command=argv, reason="stub")

    run_passive(engagement, runner=runner)
    assert engagement.registrar == "Example Registrar"
    assert engagement.org == "Stub Org"
    assert any(c.value == "admin@example.com" for c in engagement.contacts)
    names = {h.name for h in engagement.hosts}
    assert "example.com" in names
    assert "api.example.com" in names
    assert "notexample.com" not in names
