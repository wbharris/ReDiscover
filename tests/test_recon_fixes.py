import json
import os
import stat
from pathlib import Path

from rediscover.models import (
    Assumption,
    DnsRecord,
    Engagement,
    InfoNeed,
    engagement_from_dict,
)
from rediscover.passive import (
    harvest_emails,
    parse_rdap,
    rdap_lookup_names,
    run_passive,
    whois_needs_rdap,
)
from rediscover.pipeline import recon
from rediscover.report import to_json, to_markdown
from rediscover.tools import is_elf, which


BANNER = """
*******************************************************************
* theHarvester 5.0.0                                              *
* Coded by Christian Martorella                                   *
* cmartorella@edge-security.com                                   *
*******************************************************************
[*] Target: ginandjuice.shop

[*] No emails found.
"""


def test_harvest_emails_skips_banner_and_no_emails():
    assert harvest_emails(BANNER) == []


def test_harvest_emails_keeps_real_hits():
    blob = (
        "[*] Target: example.com\n"
        "[*] Emails found:\n"
        "ops@example.com\n"
    )
    assert harvest_emails(blob) == ["ops@example.com"]


def test_whois_needs_rdap_retired_and_malformed():
    assert whois_needs_rdap(
        "Notice: Effective May 1, 2026, the WHOIS service has been retired"
    )
    assert whois_needs_rdap("Malformed request.\n>>> Last update")
    assert not whois_needs_rdap("Registrar: Example Registrar\n")


def test_rdap_lookup_names_parent_for_hostname():
    assert rdap_lookup_names("scanme.nmap.org") == ["scanme.nmap.org", "nmap.org"]
    assert rdap_lookup_names("ginandjuice.shop") == ["ginandjuice.shop"]


def test_parse_rdap_registrar_and_ns():
    data = {
        "nameservers": [{"ldhName": "ns-110.awsdns-13.com."}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "GoDaddy.com LLC"]],
                ],
            }
        ],
    }
    registrar, org, nses = parse_rdap(data)
    assert registrar == "GoDaddy.com LLC"
    assert org == ""
    assert nses == ["ns-110.awsdns-13.com"]


def test_run_passive_rdap_when_whois_retired():
    engagement = recon("ginandjuice.shop", company="PortSwigger", offline=True)
    engagement.mode = "passive"
    engagement.tools = []
    engagement.improve = []
    engagement.assumptions = []

    rdap_body = json.dumps(
        {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy.com LLC"]]],
                }
            ],
            "nameservers": [{"ldhName": "ns-1.example.net"}],
        }
    )

    def runner(name: str, argv: list[str]):
        from rediscover.models import ToolRun

        if name == "whois":
            return ToolRun(
                name="whois",
                status="ran",
                command=argv,
                output="the WHOIS service has been retired in accordance with ICANN's RDAP transition",
            )
        return ToolRun(name=name, status="skipped", command=argv, reason="stub")

    def fetch(url, headers=None, timeout=25):
        assert "rdap.org/domain/ginandjuice.shop" in url
        return 200, rdap_body, ""

    run_passive(engagement, runner=runner, quick=True, fetch=fetch)
    assert engagement.registrar == "GoDaddy.com LLC"
    assert engagement.name_servers == ["ns-1.example.net"]
    assert any(t.name == "rdap" and t.status == "ran" for t in engagement.tools)
    assert not any(c.value.lower().endswith("@edge-security.com") for c in engagement.contacts)


def test_run_passive_drops_harvester_banner_email():
    engagement = recon("example.com", offline=True)
    engagement.mode = "passive"
    engagement.tools = []

    def runner(name: str, argv: list[str]):
        from rediscover.models import ToolRun

        if name == "whois":
            return ToolRun(
                name="whois",
                status="ran",
                command=argv,
                output="Registrar: Example Registrar\n",
            )
        if name == "theHarvester":
            return ToolRun(name=name, status="ran", command=argv, output=BANNER)
        return ToolRun(name=name, status="skipped", command=argv, reason="stub")

    run_passive(engagement, runner=runner, quick=True, fetch=lambda *a, **k: (404, "", "no"))
    assert engagement.contacts == []
    assert engagement.registrar == "Example Registrar"
    assert not any(t.name == "rdap" for t in engagement.tools)


def test_engagement_from_dict_roundtrip_dns_honesty():
    engagement = Engagement(
        domain="example.com",
        mode="active",
        registrar="Example Registrar",
        dns=[DnsRecord(type="A", value="93.184.216.34")],
        assumptions=[
            Assumption(field="live_lookups", assumed="ok", because="test"),
        ],
        improve=[InfoNeed(question="nmap?", why_it_matters="ports")],
    )
    loaded = engagement_from_dict(json.loads(to_json(engagement)))
    assert loaded.dns[0].value == "93.184.216.34"
    assert loaded.assumptions[0].field == "live_lookups"
    assert loaded.improve[0].question == "nmap?"
    md = to_markdown(loaded)
    assert "`A` 93.184.216.34" in md
    assert "nmap?" in md


def test_which_prefers_elf_httpx(tmp_path: Path, monkeypatch):
    import rediscover.tools as tools_mod

    py_dir = tmp_path / "py"
    elf_dir = tmp_path / "elf"
    py_dir.mkdir()
    elf_dir.mkdir()
    py_bin = py_dir / "httpx"
    elf_bin = elf_dir / "httpx"
    py_bin.write_text("#!/usr/bin/python3\nfrom httpx import main\n")
    py_bin.chmod(py_bin.stat().st_mode | stat.S_IEXEC)
    elf_bin.write_bytes(b"\x7fELF" + b"\x00" * 32)
    elf_bin.chmod(elf_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(tools_mod, "_EXTRA_BIN_DIRS", ())
    monkeypatch.setenv("PATH", f"{py_dir}{os.pathsep}{elf_dir}")
    monkeypatch.setattr(os, "environ", os.environ)
    assert not is_elf(py_bin)
    assert is_elf(elf_bin)
    picked = which("httpx")
    assert picked is not None
    assert Path(picked).resolve() == elf_bin.resolve()
