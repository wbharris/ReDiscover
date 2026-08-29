"""Address helpers for active recon."""

from __future__ import annotations

import ipaddress


def parse_ipv4(value: str) -> ipaddress.IPv4Address | None:
    text = (value or "").strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return addr
    return None


def is_private_ipv4(value: str) -> bool:
    addr = parse_ipv4(value)
    if addr is None:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def public_ipv4s(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        addr = parse_ipv4(value)
        if addr is None or is_private_ipv4(value):
            continue
        text = str(addr)
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out
