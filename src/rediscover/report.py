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


def _tool_counts(engagement: Engagement) -> str:
    ran = sum(1 for t in engagement.tools if t.status == "ran")
    skipped = sum(1 for t in engagement.tools if t.status == "skipped")
    failed = sum(1 for t in engagement.tools if t.status == "failed")
    planned = sum(1 for t in engagement.tools if t.status == "planned")
    counts = f"{ran} ran, {skipped} skipped, {failed} failed"
    if planned:
        counts += f", {planned} planned"
    return counts


def to_markdown(engagement: Engagement) -> str:
    company = engagement.company or "(not set)"
    dns_lines = [f"`{r.type}` {r.value}" for r in engagement.dns]
    host_lines = []
    for host in engagement.hosts:
        bits = [host.name]
        if host.ips:
            bits.append(f"({', '.join(host.ips)})")
        if host.private:
            bits.append("private")
        if host.status is not None:
            bits.append(f"HTTP {host.status}")
        if host.title:
            bits.append(host.title)
        if host.server:
            bits.append(host.server)
        if host.technologies:
            bits.append(", ".join(host.technologies))
        if host.url:
            bits.append(host.url)
        src = f" — {host.source}" if host.source else ""
        host_lines.append(" ".join(bits) + src)
    contact_lines = [f"{c.kind}: {c.value} ({c.source})" for c in engagement.contacts]
    link_lines = [f"[{link.title}]({link.url})" for link in engagement.links]
    squat_lines = list(engagement.squatting)
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
    nmap_hosts = [h for h in engagement.hosts if h.nmap]
    nmap_block = nmap_hosts[0].nmap if nmap_hosts else ""

    if engagement.kind == "person":
        return f"""# ReDiscover™ — {engagement.title}

1. Engagement summary  
2. Search URLs  
3. Sources  
4. Confidence and what would improve this  

## 1. Engagement summary

| Field | Value |
|-------|-------|
| Person | {engagement.title} |
| Mode | `{engagement.mode}` |
| Search URLs | {len(engagement.links)} |
| Tools | {_tool_counts(engagement)} |

These are **search pages** for an authorized assessment. They are not a confirmation of identity.

## 2. Search URLs

{_bullets(link_lines)}

## 3. Sources

{_bullets(tool_lines, empty="No tools recorded (URLs only unless --open).")}

## 4. Confidence and what would improve this

Assumptions:

{_bullets(assume_lines, empty="None recorded.")}

What would improve this:

{_bullets(improve_lines, empty="Nothing listed.")}
"""

    nmap_section = ""
    if nmap_block:
        nmap_section = f"""
## 9. Nmap

```
{nmap_block}
```
"""

    return f"""# ReDiscover™ — {engagement.title}

1. Engagement summary  
2. Domain identity  
3. DNS  
4. Hosts / subdomains  
5. People and emails  
6. Lookalike domains  
7. Sources  
8. Confidence and what would improve this  

## 1. Engagement summary

| Field | Value |
|-------|-------|
| Domain | `{engagement.domain}` |
| Company | {company} |
| Mode | `{engagement.mode}` |
| Hosts | {len(engagement.hosts)} |
| DNS records | {len(engagement.dns)} |
| Contacts | {len(engagement.contacts)} |
| Lookalikes | {len(engagement.squatting)} |
| Tools | {_tool_counts(engagement)} |

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

## 6. Lookalike domains

{_bullets(squat_lines)}

## 7. Sources

{_bullets(tool_lines, empty="No tools recorded.")}

## 8. Confidence and what would improve this

Assumptions:

{_bullets(assume_lines, empty="None recorded.")}

What would improve this:

{_bullets(improve_lines, empty="Nothing listed.")}
{nmap_section}"""
