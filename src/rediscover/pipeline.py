"""Build an engagement case from a domain or person."""

from __future__ import annotations

from collections.abc import Callable

from rediscover.active import plan_active, run_active
from rediscover.enrich import plan_enrich, run_enrich
from rediscover.models import Assumption, Engagement, Host, InfoNeed, ToolRun
from rediscover.passive import plan_passive, run_passive, validate_domain
from rediscover.person import open_person_links, person_case, plan_person
from rediscover.roster import HOST_SOURCES, MAX_URLS, URL_SOURCES

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
    if not any(t.name in HOST_SOURCES and t.status == "ran" for t in engagement.tools):
        engagement.improve.append(
            InfoNeed(
                question="Install subfinder, assetfinder, findomain, amass, or sublist3r",
                why_it_matters="Passive subdomain coverage",
            )
        )
    url_tools = [t for t in engagement.tools if t.name in URL_SOURCES]
    if url_tools and not any(t.status == "ran" for t in url_tools):
        engagement.improve.append(
            InfoNeed(
                question="Install gau, waybackurls, or urlfinder",
                why_it_matters="Historical URLs from public archives",
            )
        )
    if len(engagement.urls) >= MAX_URLS:
        engagement.assumptions.append(
            Assumption(
                field="urls",
                assumed=f"capped at {MAX_URLS}",
                because="archive tools can return more than the case keeps",
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
    passive: bool = False,
    active: bool | None = None,
    nmap: bool | None = None,
    max_hosts: int = 25,
    enrich: bool | None = None,
    runner: Runner | None = None,
    fetch=None,
) -> Engagement:
    """One recon: roster, enrich, then probes, merged into one case.

    Defaults are the full pass. ``--passive`` skips HTTP, naabu, and nmap.
    ``offline`` stays a skeleton unless active/nmap/enrich are passed explicitly.
    """
    target = validate_domain(domain)
    if passive and (active or nmap):
        raise ValueError("--passive skips HTTP probes and port scans")
    if passive:
        active = False
        nmap = False
    if active is None:
        active = not offline
    if nmap is None:
        nmap = bool(active)
    if enrich is None:
        enrich = not offline
    if nmap and not active:
        raise ValueError("--nmap requires --active")

    def _fill(engagement: Engagement) -> None:
        # Enrich before probes so crt.sh and homepage names are on the host list.
        if enrich:
            if dry_run:
                engagement.tools.extend(plan_enrich(target))
            else:
                run_enrich(engagement, fetcher=fetch)
        if active:
            if dry_run:
                engagement.tools.extend(plan_active(nmap=nmap))
            else:
                if engagement.mode != "dry-run":
                    engagement.mode = "active"
                run_active(engagement, runner, nmap=bool(nmap), max_hosts=max_hosts)
            engagement.improve = [
                item
                for item in engagement.improve
                if "Probe new enrich hosts" not in item.question
            ]

    if dry_run:
        engagement = Engagement(
            domain=target, company=company.strip(), mode="dry-run"
        )
        engagement.tools = plan_passive(target, quick=quick)
        engagement.hosts = [Host(name=target, source="intake")]
        _fill(engagement)
        _honesty(engagement)
        return engagement
    if offline:
        engagement = Engagement(
            domain=target, company=company.strip(), mode="offline"
        )
        engagement.hosts = [Host(name=target, source="intake")]
        _fill(engagement)
        _honesty(engagement)
        return engagement
    engagement = Engagement(
        domain=target,
        company=company.strip(),
        mode="active" if active else "passive",
    )
    run_passive(engagement, runner, quick=quick, fetch=fetch)
    _fill(engagement)
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
