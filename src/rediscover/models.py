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


def _rows(cls, rows: list | None):
    fields = set(cls.__dataclass_fields__)
    out = []
    for row in rows or []:
        if isinstance(row, dict):
            out.append(cls(**{k: v for k, v in row.items() if k in fields}))
    return out


def engagement_from_dict(data: dict[str, Any]) -> Engagement:
    return Engagement(
        kind=str(data.get("kind") or "domain"),
        domain=str(data.get("domain") or ""),
        company=str(data.get("company") or ""),
        person_first=str(data.get("person_first") or ""),
        person_last=str(data.get("person_last") or ""),
        mode=str(data.get("mode") or "passive"),
        whois_raw=str(data.get("whois_raw") or ""),
        registrar=str(data.get("registrar") or ""),
        org=str(data.get("org") or ""),
        name_servers=list(data.get("name_servers") or []),
        dns=_rows(DnsRecord, data.get("dns")),
        hosts=_rows(Host, data.get("hosts")),
        contacts=_rows(Contact, data.get("contacts")),
        links=_rows(SearchLink, data.get("links")),
        squatting=[str(item) for item in (data.get("squatting") or [])],
        tools=_rows(ToolRun, data.get("tools")),
        assumptions=_rows(Assumption, data.get("assumptions")),
        improve=_rows(InfoNeed, data.get("improve")),
    )
