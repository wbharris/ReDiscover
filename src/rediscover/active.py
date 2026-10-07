"""Opt-in active recon: resolve, HTTP probe, optional top ports."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from rediscover import __version__
from rediscover.models import Engagement, Host, ToolRun
from rediscover.passive import _host_from_line
from rediscover.netutil import is_private_ipv4, parse_ipv4, public_ipv4s
from rediscover.tools import planned, run, which

Runner = Callable[[str, list[str]], ToolRun]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_STATUS_RE = re.compile(r"HTTP/\S+\s+(\d{3})")


def _step(
    name: str,
    argv: list[str],
    timeout: int,
    runner: Runner | None,
    *,
    stdin: str | None = None,
) -> ToolRun:
    if runner is not None:
        return runner(name, argv)
    return run(name, argv, timeout=timeout, stdin=stdin)


def _by_name(engagement: Engagement) -> dict[str, Host]:
    return {host.name: host for host in engagement.hosts}


def resolve_argv(name: str) -> list[str]:
    if which("dig"):
        return ["dig", "+short", "A", name]
    return ["host", "-t", "A", name]


def parse_resolve(output: str) -> list[str]:
    ips: list[str] = []
    for line in output.splitlines():
        token = line.strip().split()[-1] if line.strip() else ""
        token = token.rstrip(".")
        if token.count(".") == 3 and not is_private_ipv4(token):
            try:
                parts = [int(p) for p in token.split(".")]
            except ValueError:
                continue
            if all(0 <= p <= 255 for p in parts):
                ips.append(token)
        elif token.count(".") == 3 and is_private_ipv4(token):
            ips.append(token)
    return ips


def probe_targets(engagement: Engagement, max_hosts: int) -> list[Host]:
    ranked = sorted(
        engagement.hosts,
        key=lambda h: (h.name != engagement.domain, h.private, h.name),
    )
    chosen: list[Host] = []
    for host in ranked:
        if host.private:
            continue
        if host.ips and not public_ipv4s(host.ips) and all(is_private_ipv4(ip) for ip in host.ips):
            continue
        chosen.append(host)
        if len(chosen) >= max_hosts:
            break
    return chosen


def dnsx_argv() -> list[str]:
    return ["dnsx", "-silent", "-a", "-resp"]


# Kali naabu 2.6.1 accepts -top-ports only as full, 100, or 1000.
# This set is the nmap-services frequency list behind `nmap --top-ports 20`.
NMAP_TOP_20_PORTS = "80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900"


def naabu_argv(ips: list[str] | None = None) -> list[str]:
    argv = [
        "naabu",
        "-silent",
        "-duc",
        "-no-stdin",
        "-p",
        NMAP_TOP_20_PORTS,
        "-rate",
        "200",
    ]
    if ips:
        argv.extend(["-host", ",".join(ips)])
    return argv


def nmap_argv(ips: list[str] | None = None) -> list[str]:
    argv = ["nmap", "-Pn", "-sV", "--top-ports", "20", "-oN", "-"]
    if ips:
        argv.extend(ips)
    return argv


def tlsx_argv() -> list[str]:
    return ["tlsx", "-silent", "-dns"]


TLS_HOST_CAP = 50


def _tlsx_names(line: str) -> list[str]:
    text = line.strip()
    if not text or text.startswith("["):
        return []
    if "[" in text and text.endswith("]"):
        inner = text[text.find("[") + 1 : -1]
        return [part.strip() for part in inner.split(",") if part.strip()]
    token = text.split()[0]
    return [token.split(":")[0]]


def apply_tlsx(engagement: Engagement, output: str, *, limit: int = TLS_HOST_CAP) -> int:
    """Keep in-scope certificate names. New names stay unconfirmed and are not re-probed."""
    by_name = _by_name(engagement)
    added = 0
    for line in (output or "").splitlines():
        for raw in _tlsx_names(line):
            host = _host_from_line(engagement.domain, raw, "tlsx")
            if host is None:
                continue
            existing = by_name.get(host.name)
            if existing is None:
                if added >= limit:
                    continue
                host.confirmed = False
                engagement.hosts.append(host)
                by_name[host.name] = host
                added += 1
            elif "tlsx" not in existing.source.split(","):
                existing.source = f"{existing.source},tlsx" if existing.source else "tlsx"
    engagement.hosts.sort(key=lambda item: item.name)
    return added


def whatweb_argv(urls: list[str] | None = None) -> list[str]:
    # --quiet keeps the brief line off stdout. --log-json=- is then one JSON value.
    argv = ["whatweb", "--quiet", "--no-errors", "--log-json=-"]
    if urls:
        argv.extend(urls)
    return argv


def plan_active(*, nmap: bool = False) -> list[ToolRun]:
    steps: list[ToolRun] = [planned("dnsx", dnsx_argv()), planned("tlsx", tlsx_argv())]
    if which("httpx"):
        steps.append(planned("httpx", ["httpx", "-silent", "-json", "-timeout", "8"]))
    else:
        steps.append(planned("curl", ["curl", "-sS", "-I", "-L", "-m", "10"]))
    if which("whatweb"):
        steps.append(planned("whatweb", whatweb_argv()))
    if nmap:
        steps.append(planned("naabu", naabu_argv()))
        steps.append(planned("nmap", nmap_argv()))
    return steps


_DNSX_LINE = re.compile(
    r"^([A-Za-z0-9._-]+)\s+\[A\]\s+\[?(\d{1,3}(?:\.\d{1,3}){3})\]?\s*$"
)


def apply_dnsx(engagement: Engagement, output: str) -> None:
    hosts = _by_name(engagement)
    for line in (output or "").splitlines():
        match = _DNSX_LINE.match(line.strip())
        if match is None:
            continue
        name = match.group(1).lower().rstrip(".").removeprefix("www.")
        ip = match.group(2)
        if parse_ipv4(ip) is None:
            continue
        host = hosts.get(name)
        if host is None or ip in host.ips:
            continue
        host.ips.append(ip)
        host.private = bool(host.ips) and all(is_private_ipv4(item) for item in host.ips)


def apply_naabu(engagement: Engagement, output: str, targets: list[Host]) -> None:
    by_ip: dict[str, list[Host]] = {}
    by_name = {host.name: host for host in targets}
    for host in targets:
        for ip in host.ips:
            by_ip.setdefault(ip, []).append(host)
    for line in (output or "").splitlines():
        text = line.strip()
        if ":" not in text:
            continue
        left, _, port_s = text.rpartition(":")
        if not port_s.isdigit():
            continue
        port = int(port_s)
        if not 1 <= port <= 65535:
            continue
        label = f"{port}/tcp"
        owners = by_ip.get(left) or []
        named = by_name.get(left.lower().rstrip("."))
        if named is not None and named not in owners:
            owners.append(named)
        for host in owners:
            if label not in host.ports:
                host.ports.append(label)


def apply_httpx_jsonl(engagement: Engagement, output: str) -> None:
    hosts = _by_name(engagement)
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = str(row.get("input") or row.get("host") or "").strip().lower().rstrip(".")
        name = name.removeprefix("www.")
        host = hosts.get(name)
        if host is None:
            continue
        url = str(row.get("url") or "")
        status = row.get("status_code")
        host.url = url
        if isinstance(status, int):
            host.status = status
        elif isinstance(status, str) and status.isdigit():
            host.status = int(status)
        host.title = str(row.get("title") or host.title)
        host.server = str(row.get("webserver") or host.server)
        tech = row.get("tech") or []
        if isinstance(tech, list):
            host.technologies = [str(item) for item in tech if item]
        ips = row.get("a") or row.get("host_ip")
        if isinstance(ips, list):
            for ip in ips:
                ip_s = str(ip)
                if ip_s and ip_s not in host.ips:
                    host.ips.append(ip_s)
        elif isinstance(ips, str) and ips and ips not in host.ips:
            host.ips.append(ips)
        host.private = bool(host.ips) and all(is_private_ipv4(ip) for ip in host.ips)


def apply_curl(host: Host, header: str, body: str) -> None:
    match = _STATUS_RE.search(header)
    if match:
        host.status = int(match.group(1))
    title = _TITLE_RE.search(body)
    if title:
        host.title = re.sub(r"\s+", " ", title.group(1)).strip()[:200]
    for line in header.splitlines():
        if line.lower().startswith("server:"):
            host.server = line.split(":", 1)[1].strip()
            break


_NMAP_OPEN = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+")


def _json_rows(text: str) -> list:
    """WhatWeb JSON, including a brief line inserted before the closing bracket."""
    decoder = json.JSONDecoder()
    start = text.find("[")
    if start >= 0:
        try:
            value, _end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            value = None
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
    rows: list = []
    idx = 0
    while True:
        brace = text.find("{", idx)
        if brace < 0:
            break
        try:
            value, end = decoder.raw_decode(text[brace:])
        except json.JSONDecodeError:
            idx = brace + 1
            continue
        if isinstance(value, dict):
            rows.append(value)
        idx = brace + max(end, 1)
    return rows


def apply_nmap(engagement: Engagement, output: str, targets: list[Host]) -> None:
    """Copy open ports from nmap -oN text onto the hosts that were scanned."""
    text = output or ""
    by_ip: dict[str, list[Host]] = {}
    by_name = {host.name: host for host in targets}
    for host in targets:
        for ip in host.ips:
            by_ip.setdefault(ip, []).append(host)
        if text and any(ip in text for ip in host.ips):
            host.nmap = text[:8000]
    parts = re.split(r"(?m)^Nmap scan report for ", text)
    for part in parts[1:]:
        header, _, body = part.partition("\n")
        owners: list[Host] = []
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", header):
            for host in by_ip.get(ip, []):
                if host not in owners:
                    owners.append(host)
        name = header.split("(", 1)[0].strip().lower().rstrip(".").removeprefix("www.")
        named = by_name.get(name)
        if named is not None and named not in owners:
            owners.append(named)
        if not owners:
            continue
        for line in body.splitlines():
            match = _NMAP_OPEN.match(line.strip())
            if match is None:
                continue
            label = f"{match.group(1)}/{match.group(2)}"
            for host in owners:
                if label not in host.ports:
                    host.ports.append(label)
                if not host.nmap:
                    host.nmap = text[:8000]


def apply_whatweb_json(engagement: Engagement, output: str) -> None:
    text = (output or "").strip()
    if not text:
        return
    rows = _json_rows(text)
    if not rows:
        return
    hosts = _by_name(engagement)
    for row in rows:
        if not isinstance(row, dict):
            continue
        target = str(row.get("target") or row.get("http_host") or "")
        name = target
        name = re.sub(r"^https?://", "", name)
        name = name.split("/", 1)[0].split(":")[0].lower().rstrip(".")
        name = name.removeprefix("www.")
        host = hosts.get(name)
        if host is None:
            continue
        plugins = row.get("plugins") or {}
        if isinstance(plugins, dict):
            extra = [str(key) for key in plugins if key]
            for item in extra:
                if item not in host.technologies:
                    host.technologies.append(item)
        status = row.get("http_status")
        if isinstance(status, int) and host.status is None:
            host.status = status


def run_active(
    engagement: Engagement,
    runner: Runner | None = None,
    *,
    nmap: bool = False,
    max_hosts: int = 25,
) -> None:
    if max_hosts < 1:
        max_hosts = 1

    pending = [host for host in engagement.hosts if not host.ips]
    for host in engagement.hosts:
        if host.ips:
            host.private = all(is_private_ipv4(ip) for ip in host.ips)
    # dnsx reads the host list on stdin. An injected runner stays on dig/host.
    if pending and runner is None and which("dnsx"):
        payload = "\n".join(host.name for host in pending) + "\n"
        tool = _step("dnsx", dnsx_argv(), 60, None, stdin=payload)
        engagement.tools.append(tool)
        if tool.status == "ran":
            if tool.output:
                apply_dnsx(engagement, tool.output)
            pending = []
    elif pending and runner is None:
        engagement.tools.append(
            ToolRun(
                name="dnsx",
                status="skipped",
                command=dnsx_argv(),
                reason="dnsx not installed",
            )
        )
    for host in pending:
        tool = _step(f"resolve:{host.name}", resolve_argv(host.name), 20, runner)
        engagement.tools.append(tool)
        if tool.status == "ran" and tool.output:
            host.ips = parse_resolve(tool.output)
            host.private = bool(host.ips) and all(is_private_ipv4(ip) for ip in host.ips)

    targets = probe_targets(engagement, max_hosts)
    if not targets:
        engagement.tools.append(
            ToolRun(
                name="http-probe",
                status="skipped",
                reason="no public hosts to probe",
            )
        )
        return

    if which("httpx") or runner is not None:
        argv = ["httpx", "-silent", "-json", "-timeout", "8", "-title", "-web-server", "-tech-detect"]
        for host in targets:
            argv.extend(["-u", host.name])
        tool = _step("httpx", argv, 120, runner)
        engagement.tools.append(tool)
        if tool.status == "ran" and tool.output:
            apply_httpx_jsonl(engagement, tool.output)
    else:
        for host in targets:
            url = f"https://{host.name}"
            head = _step(
                f"curl:{host.name}",
                [
                    "curl",
                    "-sS",
                    "-L",
                    "-m",
                    "10",
                    "-D",
                    "-",
                    "-o",
                    "-",
                    "-A",
                    f"ReDiscover/{__version__}",
                    url,
                ],
                15,
                runner,
            )
            engagement.tools.append(head)
            if head.status == "ran" and head.output:
                parts = head.output.split("\r\n\r\n", 1)
                if len(parts) == 1:
                    parts = head.output.split("\n\n", 1)
                header = parts[0]
                body = parts[1] if len(parts) > 1 else ""
                host.url = url
                apply_curl(host, header, body)

    alive_urls = [host.url for host in targets if host.url and host.status]
    if which("whatweb") and alive_urls:
        tool = _step("whatweb", whatweb_argv(alive_urls[:10]), 90, runner)
        engagement.tools.append(tool)
        if tool.status == "ran" and tool.output:
            apply_whatweb_json(engagement, tool.output)
    elif which("whatweb"):
        engagement.tools.append(
            ToolRun(name="whatweb", status="skipped", reason="no HTTP URLs from probe")
        )

    payload = "\n".join(host.name for host in targets) + "\n"
    tls = _step(
        "tlsx",
        tlsx_argv(),
        90,
        None if runner is None else runner,
        stdin=payload if runner is None else None,
    )
    engagement.tools.append(tls)
    if tls.status == "ran" and tls.output:
        added = apply_tlsx(engagement, tls.output)
        note = f"{added} in-scope names"
        tls.reason = f"{tls.reason}; {note}" if tls.reason else note

    if not nmap:
        return
    ips: list[str] = []
    for host in targets:
        ips.extend(public_ipv4s(host.ips))
    ips = list(dict.fromkeys(ips))[:max_hosts]
    if not ips:
        engagement.tools.append(
            ToolRun(name="naabu", status="skipped", command=naabu_argv(), reason="no public IPv4s")
        )
        engagement.tools.append(
            ToolRun(name="nmap", status="skipped", command=nmap_argv(), reason="no public IPv4s")
        )
        return
    naabu = _step("naabu", naabu_argv(ips), 120, runner)
    engagement.tools.append(naabu)
    if naabu.status == "ran" and naabu.output:
        apply_naabu(engagement, naabu.output, targets)
    nmap_tool = _step("nmap", nmap_argv(ips), 180, runner)
    engagement.tools.append(nmap_tool)
    if nmap_tool.status == "ran" and nmap_tool.output:
        apply_nmap(engagement, nmap_tool.output, targets)
