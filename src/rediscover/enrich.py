"""Public enrich: crt.sh, GitHub (PAT), homepage. Candidates stay unconfirmed."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlparse

from rediscover.httpfetch import http_get
from rediscover.keys import github_token
from rediscover.models import Assumption, Contact, Engagement, Host, InfoNeed, ToolRun
from rediscover.passive import DOMAIN_RE, _EMAIL_RE, _PRIVACY_EMAIL
from rediscover.tools import planned, which

Fetcher = Callable[..., tuple[int, str, str]]
MAX_HOSTS = 200
MAX_CONTACTS = 80


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.mailto: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: v or "" for k, v in attrs}
        if tag == "a":
            href = ad.get("href", "")
            if href.startswith("mailto:"):
                self.mailto.append(href.split(":", 1)[1].split("?", 1)[0])
            elif href:
                self.hrefs.append(href)


def _belongs(name: str, domain: str) -> bool:
    name = name.strip().lower().rstrip(".")
    name = name.removeprefix("*.")
    if not DOMAIN_RE.fullmatch(name):
        return False
    return name == domain or name.endswith("." + domain)


def parse_crtsh(body: str, domain: str) -> list[str]:
    names: list[str] = []
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return names
    if not isinstance(rows, list):
        return names
    for row in rows:
        if not isinstance(row, dict):
            continue
        blob = str(row.get("name_value") or row.get("common_name") or "")
        for part in re.split(r"[\s,]+", blob):
            host = part.strip().lower().rstrip(".")
            host = host.removeprefix("*.")
            if _belongs(host, domain):
                names.append(host)
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
        if len(out) >= MAX_HOSTS:
            break
    return out


def parse_github_search(body: str, domain: str) -> tuple[list[str], list[str]]:
    hosts: list[str] = []
    emails: list[str] = []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return hosts, emails
    blob = json.dumps(data)
    for match in _EMAIL_RE.findall(blob):
        if _PRIVACY_EMAIL.search(match):
            continue
        if match.lower().endswith("@" + domain) or domain in match.lower():
            emails.append(match)
    for token in re.findall(r"[A-Za-z0-9._-]+\." + re.escape(domain), blob, flags=re.I):
        host = token.lower().rstrip(".")
        if _belongs(host, domain):
            hosts.append(host)
    if _belongs(domain, domain):
        pass
    seen_h: set[str] = set()
    seen_e: set[str] = set()
    return (
        [h for h in hosts if not (h in seen_h or seen_h.add(h))],
        [e for e in emails if not (e.lower() in seen_e or seen_e.add(e.lower()))],
    )


def parse_homepage(html: str, domain: str, base: str) -> tuple[list[str], list[str]]:
    hosts: list[str] = []
    emails: list[str] = []
    parser = _PageParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    for mail in parser.mailto + _EMAIL_RE.findall(html):
        mail = mail.strip()
        if not mail or _PRIVACY_EMAIL.search(mail):
            continue
        if mail.lower().endswith("@" + domain):
            emails.append(mail)
    for href in parser.hrefs:
        abs_url = urljoin(base, href)
        host = (urlparse(abs_url).hostname or "").lower().rstrip(".")
        if host and _belongs(host, domain):
            hosts.append(host)
    for token in re.findall(r"[A-Za-z0-9._-]+\." + re.escape(domain), html, flags=re.I):
        if _belongs(token.lower(), domain):
            hosts.append(token.lower())
    seen_h: set[str] = set()
    seen_e: set[str] = set()
    return (
        [h for h in hosts if not (h in seen_h or seen_h.add(h))][:MAX_HOSTS],
        [e for e in emails if not (e.lower() in seen_e or seen_e.add(e.lower()))][:MAX_CONTACTS],
    )


def _add_host(engagement: Engagement, name: str, source: str) -> None:
    name = name.lower().rstrip(".")
    existing = next((h for h in engagement.hosts if h.name == name), None)
    if existing:
        if source not in existing.source.split(","):
            existing.source = f"{existing.source},{source}" if existing.source else source
        return
    engagement.hosts.append(Host(name=name, source=source, confirmed=False))


def _add_contact(engagement: Engagement, value: str, source: str) -> None:
    low = value.lower()
    if any(c.value.lower() == low for c in engagement.contacts):
        return
    engagement.contacts.append(Contact(value=value, kind="email", source=source))


def plan_enrich(domain: str) -> list[ToolRun]:
    steps = [planned("crt.sh", ["GET", f"https://crt.sh/?q={domain}&output=json"])]
    token = github_token()
    if token:
        steps.append(planned("github-search", ["GET", "https://api.github.com/search/code"]))
    else:
        steps.append(
            ToolRun(
                name="github-search",
                status="skipped",
                reason="no GitHub token in GITHUB_TOKEN or ~/.theHarvester/api-keys.yaml",
            )
        )
    steps.append(planned("homepage", ["GET", f"https://{domain}"]))
    return steps


def run_enrich(
    engagement: Engagement,
    *,
    fetcher: Fetcher | None = None,
) -> None:
    get = fetcher or http_get
    domain = engagement.domain
    if not domain:
        return

    crt_url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
    status, body, err = get(crt_url, timeout=40)
    if status == 200 and body.strip().startswith("["):
        names = parse_crtsh(body, domain)
        for name in names:
            _add_host(engagement, name, "crt.sh")
        engagement.tools.append(
            ToolRun(
                name="crt.sh",
                status="ran",
                command=["GET", crt_url],
                reason=f"{len(names)} names",
            )
        )
    else:
        engagement.tools.append(
            ToolRun(
                name="crt.sh",
                status="failed" if status else "failed",
                command=["GET", crt_url],
                reason=err or f"HTTP {status}",
                output=body[:300],
            )
        )

    token = github_token()
    if not token:
        engagement.tools.append(
            ToolRun(
                name="github-search",
                status="skipped",
                reason="no GitHub token",
            )
        )
    else:
        gh_url = (
            "https://api.github.com/search/code?q="
            + quote(f'"{domain}"')
            + "&per_page=15"
        )
        status, body, err = get(
            gh_url,
            headers={
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Accept": "application/vnd.github+json",
            },
            timeout=25,
        )
        if status in {401, 403, 422} or not body.startswith("{"):
            gh_url = (
                "https://api.github.com/search/repositories?q="
                + quote(domain)
                + "&per_page=15"
            )
            status, body, err = get(
                gh_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "Accept": "application/vnd.github+json",
                },
                timeout=25,
            )
        if status == 200:
            hosts, emails = parse_github_search(body, domain)
            for name in hosts:
                _add_host(engagement, name, "github")
            for mail in emails:
                _add_contact(engagement, mail, "github")
            engagement.tools.append(
                ToolRun(
                    name="github-search",
                    status="ran",
                    command=["GET", "https://api.github.com/search"],
                    reason=f"{len(hosts)} hosts, {len(emails)} emails",
                )
            )
        else:
            engagement.tools.append(
                ToolRun(
                    name="github-search",
                    status="failed",
                    command=["GET", gh_url],
                    reason=err or f"HTTP {status}",
                )
            )

    page_url = f"https://{domain}"
    status, body, err = get(page_url, timeout=15)
    if status == 0 or status >= 400:
        page_url = f"http://{domain}"
        status, body, err = get(page_url, timeout=15)
    if status and 200 <= status < 400 and body:
        hosts, emails = parse_homepage(body, domain, page_url)
        for name in hosts:
            _add_host(engagement, name, "homepage")
        for mail in emails:
            _add_contact(engagement, mail, "homepage")
        engagement.tools.append(
            ToolRun(
                name="homepage",
                status="ran",
                command=["GET", page_url],
                reason=f"HTTP {status}; {len(hosts)} hosts, {len(emails)} emails",
            )
        )
    else:
        engagement.tools.append(
            ToolRun(
                name="homepage",
                status="skipped" if status in {0, 403, 404} else "failed",
                command=["GET", page_url],
                reason=err or f"HTTP {status}",
            )
        )

    engagement.hosts.sort(key=lambda h: h.name)
    if not any(a.field == "enrich_unconfirmed" for a in engagement.assumptions):
        engagement.assumptions.append(
            Assumption(
                field="enrich_unconfirmed",
                assumed="crt.sh/github/homepage hosts are not live until Active",
                because="public enrich does not resolve or HTTP-probe new names",
            )
        )
    if not any("Probe new enrich hosts" in i.question for i in engagement.improve):
        engagement.improve.append(
            InfoNeed(
                question="Probe new enrich hosts with rediscover recon --active",
                why_it_matters="CT and HTML mentions are not proof the host still answers",
            )
        )
    if which("dig") is None and which("host") is None:
        pass
