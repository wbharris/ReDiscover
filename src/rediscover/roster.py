"""Recon tools ReDiscover will call. Missing binaries are skipped, not installed."""

from __future__ import annotations

import os
from dataclasses import dataclass

from rediscover.tools import is_elf, which

# Passive host lines ReDiscover turns into case hosts.
HOST_SOURCES = frozenset(
    {
        "subfinder",
        "assetfinder",
        "findomain",
        "amass",
        "sublist3r",
        "chaos",
    }
)

# Archive URL tools. Output is capped on the case; nothing is fetched.
URL_SOURCES = frozenset({"gau", "waybackurls", "urlfinder"})

MAX_URLS = 200


@dataclass(frozen=True)
class ReconTool:
    name: str
    binary: str
    role: str
    when: str  # always | full | active | ports
    summary: str


# `recon` runs this whole roster. `--passive` skips HTTP and port tools.
# `--no-ports` skips naabu and nmap. Nothing here is an exploit scanner,
# a wordlist brute forcer, or an autonomous attack agent.
ROSTER: tuple[ReconTool, ...] = (
    ReconTool("whois", "whois", "identity", "always", "Registrar and contacts"),
    ReconTool("dig", "dig", "dns", "always", "DNS records; host is the fallback"),
    ReconTool(
        "subfinder",
        "subfinder",
        "hosts",
        "always",
        "Passive subdomains; -all unless --quick; -max-time so the list is written",
    ),
    ReconTool("assetfinder", "assetfinder", "hosts", "always", "Passive subdomains (--subs-only)"),
    ReconTool("findomain", "findomain", "hosts", "always", "Passive subdomains"),
    ReconTool("theHarvester", "theHarvester", "mail", "always", "Emails via duckduckgo"),
    ReconTool("amass", "amass", "hosts", "full", "Passive enum (skipped by --quick)"),
    ReconTool("sublist3r", "sublist3r", "hosts", "full", "Passive subdomains (skipped by --quick)"),
    ReconTool("chaos", "chaos", "hosts", "full", "Chaos subdomains; needs an API key"),
    ReconTool("dnstwist", "dnstwist", "squatting", "full", "Lookalike domains (skipped by --quick)"),
    ReconTool("gau", "gau", "urls", "full", "Historical URLs, capped (skipped by --quick)"),
    ReconTool("waybackurls", "waybackurls", "urls", "full", "Wayback URLs on stdin, capped"),
    ReconTool("urlfinder", "urlfinder", "urls", "full", "Passive URLs, capped (skipped by --quick)"),
    ReconTool("dnsx", "dnsx", "resolve", "active", "Bulk A lookup; skipped by --passive"),
    ReconTool("httpx", "httpx", "http", "active", "HTTP probe; skipped by --passive"),
    ReconTool("whatweb", "whatweb", "fingerprint", "active", "Tech fingerprint; skipped by --passive"),
    ReconTool("tlsx", "tlsx", "certs", "active", "Certificate names; skipped by --passive"),
    ReconTool(
        "naabu",
        "naabu",
        "ports",
        "ports",
        "Top 20 ports via -p; skipped by --passive or --no-ports",
    ),
    ReconTool("nmap", "nmap", "ports", "ports", "Service detection; skipped by --passive or --no-ports"),
)


def chaos_key() -> str:
    return os.environ.get("CHAOS_KEY") or os.environ.get("PDCP_API_KEY") or ""


def _installed(tool: ReconTool) -> str | None:
    if tool.name == "theHarvester":
        return which("theHarvester") or which("theharvester")
    return which(tool.binary)


def inventory() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for tool in ROSTER:
        path = _installed(tool)
        note = ""
        if path is None:
            status = "missing"
            path_s = ""
        else:
            status = "installed"
            path_s = path
        if tool.name == "chaos" and path and not chaos_key():
            note = "binary present; set CHAOS_KEY or PDCP_API_KEY"
        elif tool.name == "httpx" and path and not is_elf(path):
            note = "Python httpx; want the ProjectDiscovery ELF"
        rows.append(
            {
                "name": tool.name,
                "binary": tool.binary,
                "role": tool.role,
                "when": tool.when,
                "summary": tool.summary,
                "status": status,
                "path": path_s,
                "note": note,
            }
        )
    return rows


def tools_markdown() -> str:
    lines = [
        "# ReDiscover™ recon tools",
        "",
        "| Tool | Role | When | Status | Path |",
        "|------|------|------|--------|------|",
    ]
    missing = 0
    for row in inventory():
        if row["status"] != "installed":
            missing += 1
        path = row["path"] or "—"
        note = f" ({row['note']})" if row["note"] else ""
        lines.append(
            f"| `{row['name']}` | {row['role']} | {row['when']} | {row['status']}{note} | `{path}` |"
        )
    lines.extend(
        [
            "",
            f"{missing} missing. Recon skips a missing tool and names it.",
            "ReDiscover does not install tools.",
            "HTTP and port tools run on `recon`. `--passive` skips them. `--no-ports` skips naabu and nmap.",
            "",
        ]
    )
    return "\n".join(lines)
