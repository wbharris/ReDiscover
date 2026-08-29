"""Detect and patch Discover update.sh for Kali / Kali Purple."""

from __future__ import annotations

ARP_QUESTING_ONLY = "apt install -y arp-scan/questing"
ARP_KALI = """if ! apt install -y arp-scan; then
        apt install -y arp-scan/questing || true
    fi"""

SNAP_REFRESH = "snap refresh metasploit-framework"
MSF_KALI_BLOCK = '''# Metasploit. Alphabetical: after MAN-SPIDER, before Nikto.
# Kali ships apt metasploit-framework. Snap is optional (Ubuntu-style installs).
if command -v msfconsole >/dev/null 2>&1 \\
    || { command -v snap >/dev/null 2>&1 && snap list metasploit-framework >/dev/null 2>&1; }; then
    echo -e "${BLUE}Updating Metasploit.${NC}"
    if command -v snap >/dev/null 2>&1 && snap list metasploit-framework >/dev/null 2>&1; then
        _msf_out=$(snap refresh metasploit-framework 2>&1) || true
        if echo "$_msf_out" | grep -qiE 'is up to date|already|no updates|no revisions|has no updates'; then
            echo "Already up to date."
        elif echo "$_msf_out" | grep -qiE 'access denied|error:'; then
            echo "$_msf_out" | head -3
        elif [ -n "$_msf_out" ]; then
            echo "$_msf_out" | grep -viE '^$' | head -8 || echo "Updated."
        else
            echo "Already up to date."
        fi
        unset _msf_out
    else
        apt-get -y install metasploit-framework >/dev/null
        echo "Already up to date (apt metasploit-framework)."
    fi
    echo
else
    echo -e "${YELLOW}Installing Metasploit.${NC}"
    if command -v snap >/dev/null 2>&1; then
        snap install metasploit-framework
    else
        apt-get -y install metasploit-framework
    fi
    echo
fi
'''


def arp_scan_needs_patch(text: str) -> bool:
    if ARP_QUESTING_ONLY not in text:
        return False
    return "if ! apt install -y arp-scan; then" not in text


def msf_needs_patch(text: str) -> bool:
    if SNAP_REFRESH not in text:
        return False
    return "command -v snap >/dev/null 2>&1 && snap list metasploit-framework" not in text


def patch_update_sh(text: str) -> str:
    out = text
    if arp_scan_needs_patch(out):
        out = out.replace(ARP_QUESTING_ONLY, ARP_KALI, 1)
    if msf_needs_patch(out):
        start = out.find("# Metasploit")
        nikto = out.find("# Nikto from GitHub")
        if start != -1 and nikto != -1 and start < nikto:
            out = out[:start] + MSF_KALI_BLOCK + "\n" + out[nikto:]
    return out
