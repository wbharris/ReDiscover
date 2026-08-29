"""Build an engagement case from a domain."""

from __future__ import annotations

from rediscover.models import Assumption, Engagement, Host, InfoNeed
from rediscover.passive import plan_passive, run_passive, validate_domain


def _honesty(engagement: Engagement) -> None:
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
    if engagement.mode == "passive" and not engagement.hosts:
        engagement.hosts.append(Host(name=engagement.domain, source="intake"))


def recon(
    domain: str,
    *,
    company: str = "",
    offline: bool = False,
    dry_run: bool = False,
) -> Engagement:
    target = validate_domain(domain)
    if dry_run:
        engagement = Engagement(
            domain=target, company=company.strip(), mode="dry-run"
        )
        engagement.tools = plan_passive(target)
        engagement.hosts = [Host(name=target, source="intake")]
        _honesty(engagement)
        return engagement
    if offline:
        engagement = Engagement(
            domain=target, company=company.strip(), mode="offline"
        )
        engagement.hosts = [Host(name=target, source="intake")]
        _honesty(engagement)
        return engagement
    engagement = Engagement(
        domain=target, company=company.strip(), mode="passive"
    )
    run_passive(engagement)
    _honesty(engagement)
    return engagement
