from pathlib import Path

from rediscover.cli import main
from rediscover.kali import (
    active_sh_needs_patch,
    arp_scan_needs_patch,
    msf_needs_patch,
    patch_active_sh,
    patch_update_sh,
)


UNPATCHED = """
if ! command -v arp-scan &> /dev/null; then
    echo -e "${YELLOW}Installing arpscan.${NC}"
    apt install -y arp-scan/questing
    echo
fi

# Metasploit (snap). Alphabetical: after MAN-SPIDER, before Nikto.
# Snap installs do not support msfupdate — use snap refresh.
if command -v msfconsole >/dev/null 2>&1 \\
    || snap list metasploit-framework >/dev/null 2>&1; then
    echo -e "${BLUE}Updating Metasploit.${NC}"
    _msf_out=$(snap refresh metasploit-framework 2>&1) || true
    echo
else
    echo -e "${YELLOW}Installing Metasploit.${NC}"
    snap install metasploit-framework
    echo
fi

# Nikto from GitHub (sullo/nikto)
"""


def test_detects_questing_and_snap():
    assert arp_scan_needs_patch(UNPATCHED)
    assert msf_needs_patch(UNPATCHED)


def test_patch_is_idempotent():
    once = patch_update_sh(UNPATCHED)
    assert not arp_scan_needs_patch(once)
    assert not msf_needs_patch(once)
    assert "if ! apt install -y arp-scan; then" in once
    assert "apt metasploit-framework" in once
    twice = patch_update_sh(once)
    assert twice == once


def test_doctor_cli_json(capsys):
    code = main(["doctor", "--json"])
    assert code in {0, 1}
    out = capsys.readouterr().out
    assert '"id": "discover-root"' in out
    assert '"id": "sudo-secure-path"' in out
    assert '"id": "libpostal-data"' in out
    assert '"id": "active-sh-loopback"' in out
    assert '"id": "sudo-nmap"' in out


ACTIVE_SNIPPET = '''
def is_private_ip(ip):
    if not IPV4_RE.match(ip):
        return False
    octets = [int(part) for part in ip.split(".")]
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False
'''


def test_active_sh_loopback_patch():
    assert active_sh_needs_patch(ACTIVE_SNIPPET)
    once = patch_active_sh(ACTIVE_SNIPPET)
    assert not active_sh_needs_patch(once)
    assert "octets[0] == 127" in once
    assert patch_active_sh(once) == once
