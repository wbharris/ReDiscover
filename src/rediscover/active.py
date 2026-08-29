"""Opt-in active recon: resolve, HTTP probe, optional nmap."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from rediscover.models import Engagement, Host, ToolRun
from rediscover.netutil import is_private_ipv4, public_ipv4s
from rediscover.tools import planned, run, which

Runner = Callable[[str, list[str]], ToolRun]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_STATUS_RE = re.compile(r"HTTP/\S+\s+(\d{3})")


def _step(name: str, argv: list[str], timeout: int, runner: Runner | None) -> ToolRun:
    if runner is not None:
        return runner(name, argv)
    return run(name, argv, timeout=timeout)


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


def plan_active(*, nmap: bool = False) -> list[ToolRun]:
    steps: list[ToolRun] = []
    if which("httpx"):
        steps.append(planned("httpx", ["httpx", "-silent", "-json", "-timeout", "8"]))
    else:
        steps.append(planned("curl", ["curl", "-sS", "-I", "-L", "-m", "10"]))
    if which("whatweb"):
        steps.append(planned("whatweb", ["whatweb", "--log-json=-"]))
    if nmap:
        steps.append(
            planned("nmap", ["nmap", "-Pn", "-sV", "--top-ports", "20"])
        )
    return steps


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


def apply_whatweb_json(engagement: Engagement, output: str) -> None:
    text = output.strip()
    if not text:
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    rows = data if isinstance(data, list) else [data]
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

    for host in engagement.hosts:
        if host.ips:
            host.private = all(is_private_ipv4(ip) for ip in host.ips)
            continue
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
                    "ReDiscover/0.2",
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
        argv = ["whatweb", "--log-json=-", "--no-errors", *alive_urls[:10]]
        tool = _step("whatweb", argv, 90, runner)
        engagement.tools.append(tool)
        if tool.status == "ran" and tool.output:
            apply_whatweb_json(engagement, tool.output)
    elif which("whatweb"):
        engagement.tools.append(
            ToolRun(name="whatweb", status="skipped", reason="no HTTP URLs from probe")
        )

    if not nmap:
        return
    ips: list[str] = []
    for host in targets:
        ips.extend(public_ipv4s(host.ips))
    ips = list(dict.fromkeys(ips))
    if not ips:
        engagement.tools.append(
            ToolRun(name="nmap", status="skipped", reason="no public IPv4s")
        )
        return
    argv = ["nmap", "-Pn", "-sV", "--top-ports", "20", "-oN", "-", *ips[:max_hosts]]
    tool = _step("nmap", argv, 180, runner)
    engagement.tools.append(tool)
    if tool.status == "ran" and tool.output:
        blob = tool.output
        for host in targets:
            for ip in host.ips:
                if ip in blob:
                    host.nmap = blob[:8000]
                    break
