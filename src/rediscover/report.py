"""Markdown and JSON engagement reports."""

from __future__ import annotations

import json

from rediscover.models import Engagement


def to_json(engagement: Engagement) -> str:
    return json.dumps(engagement.to_dict(), indent=2) + "\n"


def _bullets(items: list[str], empty: str = "None.") -> str:
    if not items:
        return empty
    return "\n".join(f"- {item}" for item in items)


def to_markdown(engagement: Engagement) -> str:
    company = engagement.company or "(not set)"
    ran = sum(1 for t in engagement.tools if t.status == "ran")
    skipped = sum(1 for t in engagement.tools if t.status == "skipped")
    failed = sum(1 for t in engagement.tools if t.status == "failed")
    planned = sum(1 for t in engagement.tools if t.status == "planned")

    dns_lines = [f"`{r.type}` {r.value}" for r in engagement.dns]
    host_lines = []
    for host in engagement.hosts:
        extra = f" ({', '.join(host.ips)})" if host.ips else ""
        src = f" — {host.source}" if host.source else ""
        host_lines.append(f"{host.name}{extra}{src}")
    contact_lines = [f"{c.kind}: {c.value} ({c.source})" for c in engagement.contacts]
    tool_lines = []
    for tool in engagement.tools:
        cmd = " ".join(tool.command) if tool.command else tool.name
        note = f" — {tool.reason}" if tool.reason else ""
        tool_lines.append(f"`{tool.status}` {tool.name}: `{cmd}`{note}")
    assume_lines = [
        f"{a.field}: {a.assumed} ({a.because})" for a in engagement.assumptions
    ]
    improve_lines = [
        f"{i.question} — {i.why_it_matters}" for i in engagement.improve
    ]

    counts = f"{ran} ran, {skipped} skipped, {failed} failed"
    if planned:
        counts += f", {planned} planned"

    return f"""# ReDiscover™ — {engagement.domain}

1. Engagement summary  
2. Domain identity  
3. DNS  
4. Hosts / subdomains  
5. People and emails  
6. Sources  
7. Confidence and what would improve this  

## 1. Engagement summary

| Field | Value |
|-------|-------|
| Domain | `{engagement.domain}` |
| Company | {company} |
| Mode | `{engagement.mode}` |
| Hosts | {len(engagement.hosts)} |
| DNS records | {len(engagement.dns)} |
| Contacts | {len(engagement.contacts)} |
| Tools | {counts} |

## 2. Domain identity

- Registrar: {engagement.registrar or "(unknown)"}
- Org: {engagement.org or "(unknown)"}
- Name servers: {", ".join(f"`{ns}`" for ns in engagement.name_servers) or "(none)"}

## 3. DNS

{_bullets(dns_lines)}

## 4. Hosts / subdomains

{_bullets(host_lines)}

## 5. People and emails

{_bullets(contact_lines)}

## 6. Sources

{_bullets(tool_lines, empty="No tools recorded.")}

## 7. Confidence and what would improve this

Assumptions:

{_bullets(assume_lines, empty="None recorded.")}

What would improve this:

{_bullets(improve_lines, empty="Nothing listed.")}
"""
