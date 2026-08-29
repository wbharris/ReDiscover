"""Canonical engagement case for one recon target."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ToolRun:
    name: str
    status: str  # ran | skipped | failed | planned
    command: list[str] = field(default_factory=list)
    reason: str = ""
    output: str = ""


@dataclass
class DnsRecord:
    type: str
    value: str


@dataclass
class Host:
    name: str
    ips: list[str] = field(default_factory=list)
    source: str = ""
    private: bool = False
    url: str = ""
    status: int | None = None
    title: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    nmap: str = ""
    confirmed: bool = True


@dataclass
class Contact:
    value: str
    kind: str = "email"  # email | name | org
    source: str = ""


@dataclass
class SearchLink:
    title: str
    url: str


@dataclass
class Assumption:
    field: str
    assumed: str
    because: str


@dataclass
class InfoNeed:
    question: str
    why_it_matters: str


@dataclass
class Engagement:
    kind: str = "domain"  # domain | person
    domain: str = ""
    company: str = ""
    person_first: str = ""
    person_last: str = ""
    mode: str = "passive"  # offline | dry-run | passive | active | person
    whois_raw: str = ""
    registrar: str = ""
    org: str = ""
    name_servers: list[str] = field(default_factory=list)
    dns: list[DnsRecord] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    contacts: list[Contact] = field(default_factory=list)
    links: list[SearchLink] = field(default_factory=list)
    squatting: list[str] = field(default_factory=list)
    tools: list[ToolRun] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    improve: list[InfoNeed] = field(default_factory=list)

    @property
    def title(self) -> str:
        if self.kind == "person":
            return f"{self.person_first} {self.person_last}".strip() or "person"
        return self.domain or "engagement"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def engagement_from_dict(data: dict[str, Any]) -> Engagement:
    def _hosts(rows: list) -> list[Host]:
        out: list[Host] = []
        fields = set(Host.__dataclass_fields__)
        for row in rows or []:
            if isinstance(row, dict):
                out.append(Host(**{k: v for k, v in row.items() if k in fields}))
        return out

    def _contacts(rows: list) -> list[Contact]:
        fields = set(Contact.__dataclass_fields__)
        return [
            Contact(**{k: v for k, v in row.items() if k in fields})
            for row in rows or []
            if isinstance(row, dict)
        ]

    def _tools(rows: list) -> list[ToolRun]:
        fields = set(ToolRun.__dataclass_fields__)
        return [
            ToolRun(**{k: v for k, v in row.items() if k in fields})
            for row in rows or []
            if isinstance(row, dict)
        ]

    return Engagement(
        kind=str(data.get("kind") or "domain"),
        domain=str(data.get("domain") or ""),
        company=str(data.get("company") or ""),
        mode=str(data.get("mode") or "passive"),
        whois_raw=str(data.get("whois_raw") or ""),
        registrar=str(data.get("registrar") or ""),
        org=str(data.get("org") or ""),
        name_servers=list(data.get("name_servers") or []),
        hosts=_hosts(data.get("hosts") or []),
        contacts=_contacts(data.get("contacts") or []),
        tools=_tools(data.get("tools") or []),
    )
