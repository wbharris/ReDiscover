from pathlib import Path

from rediscover.cli import main
from rediscover.kali import arp_scan_needs_patch, msf_needs_patch, patch_update_sh


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
