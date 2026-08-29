"""Passive recon: whois, DNS, subdomain tools, squatting, mail."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from rediscover.models import Contact, DnsRecord, Engagement, Host, ToolRun
from rediscover.netutil import is_private_ipv4
from rediscover.tools import planned, run, which

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$"
)

_PRIVACY_EMAIL = re.compile(
    r"privacy|whoisproxy|redacted|anonymize|identity-protect|contact-form|abuse@",
    re.I,
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")

Runner = Callable[[str, list[str]], ToolRun]


def validate_domain(value: str) -> str:
    domain = (value or "").strip().lower().rstrip(".")
    domain = domain.removeprefix("http://").removeprefix("https://")
    domain = domain.split("/", 1)[0]
    domain = domain.removeprefix("www.")
    if domain.startswith("*."):
        domain = domain[2:]
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"not a domain: {value!r}")
    return domain


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip().lower().rstrip(".")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item.strip().rstrip("."))
    return out


def parse_whois(raw: str) -> tuple[str, str, list[str], list[str]]:
    registrar = ""
    org = ""
    nses: list[str] = []
    emails: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, _, rest = stripped.partition(":")
        key_l = key.strip().lower()
        rest = rest.strip()
        if not rest:
            continue
        if key_l in {"registrar"} and not registrar:
            registrar = rest
        elif key_l in {"org", "organization", "org-name", "registrant organization"} and not org:
            org = rest
        elif key_l in {"nserver", "name server"}:
            nses.append(rest.split()[0])
    for match in _EMAIL_RE.findall(raw):
        if _PRIVACY_EMAIL.search(match):
            continue
        emails.append(match)
    return registrar, org, _unique(nses), _unique(emails)


def _dns_argv(domain: str, rtype: str) -> list[str]:
    if which("dig"):
        return ["dig", "+short", rtype, domain]
    return ["host", "-t", rtype, domain]


def _parse_dig(rtype: str, output: str) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    for line in output.splitlines():
        value = line.strip()
        if not value:
            continue
        if value.endswith("."):
            value = value[:-1]
        records.append(DnsRecord(type=rtype, value=value))
    return records


def _parse_host(rtype: str, output: str) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "not found" in line.lower() or "has no" in line.lower():
            continue
        if "mail is handled by" in line:
            records.append(DnsRecord(type="MX", value=line.rsplit(" ", 1)[-1].rstrip(".")))
        elif "name server" in line:
            records.append(DnsRecord(type="NS", value=line.rsplit(" ", 1)[-1].rstrip(".")))
        elif "address" in line and rtype in {"A", "AAAA"}:
            records.append(DnsRecord(type=rtype, value=line.rsplit(" ", 1)[-1]))
        elif "descriptive text" in line:
            text = line.split("descriptive text", 1)[-1].strip().strip('"')
            records.append(DnsRecord(type="TXT", value=text))
        elif rtype == "SOA" and "start of authority" in line.lower():
            records.append(DnsRecord(type="SOA", value=line))
        elif rtype == "CNAME" and "is an alias for" in line:
            records.append(DnsRecord(type="CNAME", value=line.rsplit(" ", 1)[-1].rstrip(".")))
    return records


def _host_from_line(domain: str, line: str, source: str) -> Host | None:
    name = line.strip().split()[0].strip().lower().rstrip(".") if line.strip() else ""
    name = name.removeprefix("www.")
    if name != domain and not name.endswith("." + domain):
        return None
    return Host(name=name, source=source)


def collect_hosts(domain: str, runs: list[ToolRun]) -> list[Host]:
    by_name: dict[str, Host] = {}
    apex = Host(name=domain, source="intake")
    by_name[domain] = apex
    for tool in runs:
        if tool.status != "ran" or not tool.output:
            continue
        if tool.name not in {"subfinder", "amass", "sublist3r"}:
            continue
        for line in tool.output.splitlines():
            host = _host_from_line(domain, line, tool.name)
            if host is None:
                continue
            existing = by_name.get(host.name)
            if existing is None:
                by_name[host.name] = host
            elif host.source not in existing.source.split(","):
                existing.source = f"{existing.source},{host.source}"
    return sorted(by_name.values(), key=lambda h: h.name)


def parse_dnstwist(output: str, domain: str) -> list[str]:
    names: list[str] = []
    text = output.strip()
    if not text:
        return names
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            token = line.split()[0].strip().rstrip(".") if line.strip() else ""
            if token and token.lower() != domain:
                names.append(token)
        return _unique(names)
    rows = data if isinstance(data, list) else [data]
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("domain") or row.get("dns_domain") or "").strip().rstrip(".")
        if name and name.lower() != domain:
            names.append(name)
    return _unique(names)


def harvest_bin() -> str:
    if which("theHarvester"):
        return "theHarvester"
    return "theharvester"


def _step(name: str, argv: list[str], timeout: int, runner: Runner | None) -> ToolRun:
    if runner is not None:
        return runner(name, argv)
    return run(name, argv, timeout=timeout)


def passive_steps(domain: str, *, quick: bool = False) -> list[tuple[str, list[str], int]]:
    steps: list[tuple[str, list[str], int]] = [("whois", ["whois", domain], 45)]
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        steps.append((f"dns-{rtype.lower()}", _dns_argv(domain, rtype), 20))
    steps.append(("subfinder", ["subfinder", "-d", domain, "-silent"], 120))
    if not quick:
        steps.append(("amass", ["amass", "enum", "-passive", "-d", domain], 180))
        steps.append(("sublist3r", ["sublist3r", "-d", domain, "-n"], 120))
        steps.append(
            (
                "dnstwist",
                ["dnstwist", "-r", "-f", "json", domain],
                180,
            )
        )
    steps.append(
        (
            "theHarvester",
            [harvest_bin(), "-d", domain, "-b", "duckduckgo"],
            120,
        )
    )
    return steps


def plan_passive(domain: str, *, quick: bool = False) -> list[ToolRun]:
    return [planned(name, argv) for name, argv, _timeout in passive_steps(domain, quick=quick)]


def run_passive(
    engagement: Engagement,
    runner: Runner | None = None,
    *,
    quick: bool = False,
) -> None:
    domain = engagement.domain
    parse_dns = _parse_dig if which("dig") else _parse_host

    for name, argv, timeout in passive_steps(domain, quick=quick):
        tool = _step(name, argv, timeout, runner)
        engagement.tools.append(tool)
        if tool.status != "ran" or not tool.output:
            continue
        if name == "whois":
            engagement.whois_raw = tool.output
            registrar, org, nses, emails = parse_whois(tool.output)
            engagement.registrar = registrar
            if org and not engagement.company:
                engagement.company = org
            engagement.org = org
            engagement.name_servers = nses
            for email in emails:
                engagement.contacts.append(Contact(value=email, kind="email", source="whois"))
        elif name.startswith("dns-"):
            rtype = name.split("-", 1)[1].upper()
            engagement.dns.extend(parse_dns(rtype, tool.output))
        elif name == "dnstwist":
            engagement.squatting = parse_dnstwist(tool.output, domain)
        elif name == "theHarvester":
            for email in _unique(_EMAIL_RE.findall(tool.output)):
                if _PRIVACY_EMAIL.search(email):
                    continue
                if any(c.value.lower() == email.lower() for c in engagement.contacts):
                    continue
                engagement.contacts.append(
                    Contact(value=email, kind="email", source="theHarvester")
                )

    merged = collect_hosts(domain, engagement.tools)
    existing = {h.name: h for h in engagement.hosts}
    apex_ips = [
        rec.value
        for rec in engagement.dns
        if rec.type == "A" and not is_private_ipv4(rec.value)
    ] + [
        rec.value
        for rec in engagement.dns
        if rec.type == "A" and is_private_ipv4(rec.value)
    ]
    for host in merged:
        prior = existing.get(host.name)
        if prior and prior.ips:
            host.ips = prior.ips
        if host.name == domain and apex_ips:
            host.ips = _unique(apex_ips)
        host.private = bool(host.ips) and all(is_private_ipv4(ip) for ip in host.ips)
    engagement.hosts = merged
