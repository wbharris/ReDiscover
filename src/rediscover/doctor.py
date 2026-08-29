"""Diagnose and fix Discover on Kali / Kali Purple."""

from __future__ import annotations

import os
import pwd
import re
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from rediscover.kali import arp_scan_needs_patch, msf_needs_patch, patch_update_sh
from rediscover.tools import which

DEFAULT_DISCOVER = Path("/opt/discover")
SUDOERS_DROPIN = Path("/etc/sudoers.d/rediscover")
SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class Finding:
    id: str
    title: str
    ok: bool
    detail: str
    fixable: bool = False
    fixed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _is_root() -> bool:
    return os.geteuid() == 0


def _operator() -> str:
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if sudo_user and sudo_user != "root":
        return sudo_user
    if not _is_root():
        return pwd.getpwuid(os.geteuid()).pw_name
    try:
        pwd.getpwnam("iceroot")
        return "iceroot"
    except KeyError:
        return "root"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _secure_path_from_sudoers() -> str:
    proc = subprocess.run(
        ["sudo", "-n", "-V"],
        capture_output=True,
        text=True,
        check=False,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    match = re.search(r'Value to override user\'s \$PATH with:\s*(\S+)', blob)
    if match:
        return match.group(1)
    text = _read(Path("/etc/sudoers"))
    for drop in sorted(Path("/etc/sudoers.d").glob("*")):
        if drop.name.startswith("."):
            continue
        text += "\n" + _read(drop)
    paths = re.findall(r'secure_path\s*=\s*"([^"]+)"', text)
    return paths[-1] if paths else ""


def _venv_pip_ok(venv: Path) -> bool:
    python = venv / "bin" / "python"
    if not python.is_file():
        return False
    proc = subprocess.run(
        [str(python), "-m", "pip", "-V"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and "pip" in (proc.stdout or "")


def _git_pull_ok(root: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        ["git", "-C", str(root), "status", "-sb"],
        capture_output=True,
        text=True,
        check=False,
    )
    err = (proc.stderr or "").strip()
    if proc.returncode == 0:
        return True, (proc.stdout or "").strip() or "git ok"
    return False, err or f"git exit {proc.returncode}"


def _recreate_venv(venv: Path, install: list[str]) -> str:
    if venv.exists():
        shutil.rmtree(venv)
    subprocess.run(["python3", "-m", "venv", str(venv)], check=True)
    pip = [str(venv / "bin" / "python"), "-m", "pip", "install", "-q"]
    subprocess.run(pip + ["-U", "pip"], check=True)
    subprocess.run(pip + install, check=True)
    return f"recreated {venv}"


def diagnose(discover_root: Path | None = None) -> list[Finding]:
    root = discover_root or DEFAULT_DISCOVER
    update_sh = root / "misc" / "update.sh"
    findings: list[Finding] = []

    script = root / "discover.sh"
    findings.append(
        Finding(
            id="discover-root",
            title="Discover clone",
            ok=script.is_file(),
            detail=str(script) if script.is_file() else f"missing {script}",
            fixable=False,
        )
    )

    git_ok, git_detail = _git_pull_ok(root) if (root / ".git").is_dir() else (False, "not a git clone")
    findings.append(
        Finding(
            id="discover-git",
            title="git status on Discover",
            ok=git_ok,
            detail=git_detail,
            fixable="dubious ownership" in git_detail or "safe.directory" in git_detail,
        )
    )

    wrapper = which("discover")
    findings.append(
        Finding(
            id="wrapper",
            title="discover on PATH",
            ok=bool(wrapper),
            detail=wrapper or "/usr/local/bin/discover missing",
            fixable=script.is_file(),
        )
    )

    arp = which("arp-scan")
    findings.append(
        Finding(
            id="arp-scan",
            title="arp-scan (Kali package, not Ubuntu questing)",
            ok=bool(arp),
            detail=arp or "arp-scan not installed",
            fixable=True,
        )
    )

    text = _read(update_sh)
    needs_sh = bool(text) and (arp_scan_needs_patch(text) or msf_needs_patch(text))
    findings.append(
        Finding(
            id="update-sh-kali",
            title="update.sh Kali patches (arp-scan, apt Metasploit)",
            ok=bool(text) and not needs_sh,
            detail=(
                "update.sh missing"
                if not text
                else (
                    "needs Kali patch"
                    if needs_sh
                    else str(update_sh)
                )
            ),
            fixable=bool(text) and needs_sh,
        )
    )

    sp = _secure_path_from_sudoers()
    has_local = "/usr/local/bin" in sp.split(":") if sp else False
    findings.append(
        Finding(
            id="sudo-secure-path",
            title="sudo secure_path includes /usr/local/bin",
            ok=has_local,
            detail=sp or "could not read secure_path",
            fixable=True,
        )
    )

    dns_venv = Path("/opt/dnsrecon-venv")
    findings.append(
        Finding(
            id="dnsrecon-venv",
            title="DNSRecon venv has pip",
            ok=_venv_pip_ok(dns_venv),
            detail=str(dns_venv / "bin/python"),
            fixable=dns_venv.exists() or Path("/opt/dnsrecon").is_dir(),
        )
    )

    sub_venv = Path("/opt/Sublist3r-venv")
    findings.append(
        Finding(
            id="sublist3r-venv",
            title="Sublist3r venv has pip",
            ok=_venv_pip_ok(sub_venv),
            detail=str(sub_venv / "bin/python"),
            fixable=sub_venv.exists() or Path("/opt/Sublist3r/sublist3r.py").is_file(),
        )
    )

    return findings


def _fix_git(root: Path, finding: Finding) -> Finding:
    operator = _operator()
    subprocess.run(
        ["git", "config", "--system", "--add", "safe.directory", str(root)],
        check=False,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "--global", "--add", "safe.directory", str(root)],
        check=False,
        capture_output=True,
    )
    if _is_root() and operator != "root":
        subprocess.run(
            ["chown", "-R", f"{operator}:{operator}", str(root)],
            check=False,
            capture_output=True,
        )
    ok, detail = _git_pull_ok(root)
    finding.ok = ok
    finding.detail = detail
    finding.fixed = ok
    return finding


def _fix_wrapper(root: Path, finding: Finding) -> Finding:
    dest = Path("/usr/local/bin/discover")
    if not _is_root():
        finding.detail = "need root to write /usr/local/bin/discover"
        return finding
    dest.write_text("#!/usr/bin/env bash\nexec /opt/discover/discover.sh \"$@\"\n", encoding="utf-8")
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    finding.ok = dest.is_file()
    finding.fixed = finding.ok
    finding.detail = str(dest)
    return finding


def _fix_arp_scan(finding: Finding) -> Finding:
    if which("arp-scan"):
        finding.ok = True
        finding.fixed = False
        finding.detail = which("arp-scan") or ""
        return finding
    if not _is_root():
        finding.detail = "need root: apt install arp-scan"
        return finding
    proc = subprocess.run(
        ["apt-get", "install", "-y", "arp-scan"],
        capture_output=True,
        text=True,
        check=False,
    )
    finding.ok = bool(which("arp-scan"))
    finding.fixed = finding.ok
    finding.detail = which("arp-scan") or (proc.stderr or proc.stdout or "apt failed")[-400:]
    return finding


def _fix_update_sh(root: Path, finding: Finding) -> Finding:
    path = root / "misc" / "update.sh"
    text = _read(path)
    if not text:
        finding.detail = f"missing {path}"
        return finding
    patched = patch_update_sh(text)
    if patched == text:
        finding.ok = True
        finding.detail = str(path)
        return finding
    path.write_text(patched, encoding="utf-8")
    finding.ok = not arp_scan_needs_patch(patched) and not msf_needs_patch(patched)
    finding.fixed = finding.ok
    finding.detail = f"patched {path}"
    return finding


def _fix_sudoers(finding: Finding) -> Finding:
    if not _is_root():
        finding.detail = f"need root to write {SUDOERS_DROPIN}"
        return finding
    body = (
        "# Managed by ReDiscover doctor — Discover Update looks for tools in /usr/local/bin\n"
        f'Defaults secure_path="{SECURE_PATH}"\n'
    )
    tmp = Path("/tmp/rediscover-sudoers")
    tmp.write_text(body, encoding="utf-8")
    tmp.chmod(0o440)
    check = subprocess.run(["visudo", "-cf", str(tmp)], capture_output=True, text=True)
    if check.returncode != 0:
        finding.detail = (check.stderr or check.stdout or "visudo failed").strip()
        return finding
    shutil.copy(tmp, SUDOERS_DROPIN)
    os.chmod(SUDOERS_DROPIN, 0o440)
    sp = _secure_path_from_sudoers()
    finding.ok = "/usr/local/bin" in (sp or "").split(":")
    finding.fixed = finding.ok
    finding.detail = sp
    return finding


def _fix_venv(finding: Finding, venv: Path, source: Path, req: list[str]) -> Finding:
    if not _is_root():
        finding.detail = f"need root to recreate {venv}"
        return finding
    if not source.exists():
        finding.detail = f"missing source {source}"
        return finding
    finding.detail = _recreate_venv(venv, req)
    finding.ok = _venv_pip_ok(venv)
    finding.fixed = finding.ok
    return finding


def apply_fixes(findings: list[Finding], discover_root: Path | None = None) -> list[Finding]:
    root = discover_root or DEFAULT_DISCOVER
    out: list[Finding] = []
    for finding in findings:
        if finding.ok or not finding.fixable:
            out.append(finding)
            continue
        if finding.id == "discover-git":
            out.append(_fix_git(root, finding))
        elif finding.id == "wrapper":
            out.append(_fix_wrapper(root, finding))
        elif finding.id == "arp-scan":
            out.append(_fix_arp_scan(finding))
        elif finding.id == "update-sh-kali":
            out.append(_fix_update_sh(root, finding))
        elif finding.id == "sudo-secure-path":
            out.append(_fix_sudoers(finding))
        elif finding.id == "dnsrecon-venv":
            out.append(
                _fix_venv(finding, Path("/opt/dnsrecon-venv"), Path("/opt/dnsrecon"), ["/opt/dnsrecon"])
            )
        elif finding.id == "sublist3r-venv":
            req = Path("/opt/Sublist3r/requirements.txt")
            args = ["-r", str(req)] if req.is_file() else []
            out.append(
                _fix_venv(finding, Path("/opt/Sublist3r-venv"), Path("/opt/Sublist3r/sublist3r.py"), args)
            )
        else:
            out.append(finding)
    return out


def to_markdown(findings: list[Finding]) -> str:
    lines = ["# ReDiscover™ doctor", ""]
    bad = sum(1 for f in findings if not f.ok)
    fixed = sum(1 for f in findings if f.fixed)
    lines.append(f"{len(findings)} checks, {bad} failing, {fixed} fixed.")
    lines.append("")
    for f in findings:
        mark = "ok" if f.ok else "FAIL"
        extra = " (fixed)" if f.fixed else ""
        lines.append(f"- `{mark}` **{f.title}**{extra} — {f.detail}")
    lines.append("")
    if any(not f.ok for f in findings):
        lines.append("Re-run `rediscover doctor --fix` as root for remaining FAIL rows.")
    else:
        lines.append("Discover Update (menu 18) can run. Prefer `sudo /opt/discover/misc/update.sh`.")
    lines.append("")
    return "\n".join(lines)
