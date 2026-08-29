"""Build an engagement case from a domain or person."""

from __future__ import annotations

from collections.abc import Callable

from rediscover.active import plan_active, run_active
from rediscover.models import Assumption, Engagement, Host, InfoNeed, ToolRun
from rediscover.passive import plan_passive, run_passive, validate_domain
from rediscover.person import open_person_links, person_case, plan_person

Runner = Callable[[str, list[str]], ToolRun]


def _honesty(engagement: Engagement) -> None:
    if engagement.mode == "dry-run":
        return
    if engagement.kind == "person":
        engagement.assumptions.append(
            Assumption(
                field="identity",
                assumed="unconfirmed",
                because="search URLs are not proof the person exists or is in-scope",
            )
        )
        engagement.improve.append(
            InfoNeed(
                question="Open the links and record confirmed profiles",
                why_it_matters="Person recon is operator review, not a dump of private records",
            )
        )
        return
    if engagement.mode == "offline":
        engagement.assumptions.append(
            Assumption(
                field="live_lookups",
                assumed="skipped",
                because="--offline",
            )
        )
        engagement.improve.append(
            InfoNeed(
                question="Run without --offline on an authorized domain",
                why_it_matters="Whois, DNS, and subdomain tools fill the case",
            )
        )
    if not any(t.name == "whois" and t.status == "ran" for t in engagement.tools):
        engagement.improve.append(
            InfoNeed(
                question="Whois for this domain",
                why_it_matters="Registrar, org, and contact emails",
            )
        )
    if not any(t.name.startswith("dns-") and t.status == "ran" for t in engagement.tools):
        engagement.improve.append(
            InfoNeed(
                question="DNS records (A/MX/NS/TXT)",
                why_it_matters="Hosts and mail/name servers",
            )
        )
    if not any(
        t.name in {"subfinder", "amass", "sublist3r"} and t.status == "ran"
        for t in engagement.tools
    ):
        engagement.improve.append(
            InfoNeed(
                question="Install subfinder, amass, or sublist3r",
                why_it_matters="Passive subdomain coverage",
            )
        )
    if engagement.mode in {"passive", "active"} and not any(
        t.name == "dnstwist" and t.status == "ran" for t in engagement.tools
    ):
        engagement.improve.append(
            InfoNeed(
                question="Run dnstwist (omit --quick)",
                why_it_matters="Registered lookalikes / squatting",
            )
        )
    if engagement.mode == "active" and not any(
        t.name in {"httpx", "curl"} or t.name.startswith("curl:")
        for t in engagement.tools
        if t.status == "ran"
    ):
        engagement.improve.append(
            InfoNeed(
                question="HTTP probe with httpx or curl",
                why_it_matters="Which hosts actually speak HTTP",
            )
        )
    if engagement.kind == "domain" and not engagement.hosts:
        engagement.hosts.append(Host(name=engagement.domain, source="intake"))


def recon(
    domain: str,
    *,
    company: str = "",
    offline: bool = False,
    dry_run: bool = False,
    quick: bool = False,
    active: bool = False,
    nmap: bool = False,
    max_hosts: int = 25,
    runner: Runner | None = None,
) -> Engagement:
    target = validate_domain(domain)
    if nmap and not active:
        raise ValueError("--nmap requires --active")
    if dry_run:
        engagement = Engagement(
            domain=target, company=company.strip(), mode="dry-run"
        )
        engagement.tools = plan_passive(target, quick=quick)
        if active:
            engagement.tools.extend(plan_active(nmap=nmap))
        engagement.hosts = [Host(name=target, source="intake")]
        _honesty(engagement)
        return engagement
    if offline:
        engagement = Engagement(
            domain=target, company=company.strip(), mode="offline"
        )
        engagement.hosts = [Host(name=target, source="intake")]
        if active:
            engagement.mode = "active"
            run_active(engagement, runner, nmap=nmap, max_hosts=max_hosts)
        _honesty(engagement)
        return engagement
    engagement = Engagement(
        domain=target,
        company=company.strip(),
        mode="active" if active else "passive",
    )
    run_passive(engagement, runner, quick=quick)
    if active:
        run_active(engagement, runner, nmap=nmap, max_hosts=max_hosts)
    _honesty(engagement)
    return engagement


def person(
    first: str,
    last: str,
    *,
    dry_run: bool = False,
    open_links: bool = False,
    runner: Runner | None = None,
) -> Engagement:
    engagement = person_case(first, last)
    if dry_run:
        engagement.mode = "dry-run"
        engagement.tools = plan_person()
        _honesty(engagement)
        return engagement
    if open_links:
        engagement.tools.extend(open_person_links(engagement.links, runner=runner))
    _honesty(engagement)
    return engagement
