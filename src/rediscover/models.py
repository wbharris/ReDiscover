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


@dataclass
class Contact:
    value: str
    kind: str = "email"  # email | name | org
    source: str = ""


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
    domain: str
    company: str = ""
    mode: str = "passive"  # offline | dry-run | passive
    whois_raw: str = ""
    registrar: str = ""
    org: str = ""
    name_servers: list[str] = field(default_factory=list)
    dns: list[DnsRecord] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    contacts: list[Contact] = field(default_factory=list)
    tools: list[ToolRun] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    improve: list[InfoNeed] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
