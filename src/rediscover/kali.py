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


# Discover Active only treats RFC1918 as private, so 127.0.0.1 is "public".
_ACTIVE_RFC1918_TAILS = (
    (
        "    if octets[0] == 192 and octets[1] == 168:\n        return True\n    return False",
        "    if octets[0] == 192 and octets[1] == 168:\n        return True\n    if octets[0] == 127:\n        return True\n    if octets[0] == 169 and octets[1] == 254:\n        return True\n    return False",
    ),
    (
        "    if o[0] == 192 and o[1] == 168:\n        return True\n    return False",
        "    if o[0] == 192 and o[1] == 168:\n        return True\n    if o[0] == 127:\n        return True\n    if o[0] == 169 and o[1] == 254:\n        return True\n    return False",
    ),
    (
        "    if o[0]==192 and o[1]==168: return True\n    return False",
        "    if o[0]==192 and o[1]==168: return True\n    if o[0]==127: return True\n    if o[0]==169 and o[1]==254: return True\n    return False",
    ),
)


def active_sh_needs_patch(text: str) -> bool:
    if "is_private" not in text:
        return False
    if "octets[0] == 127" in text or "o[0] == 127" in text or "o[0]==127" in text:
        return False
    return any(old in text for old, _new in _ACTIVE_RFC1918_TAILS)


def patch_active_sh(text: str) -> str:
    out = text
    for old, new in _ACTIVE_RFC1918_TAILS:
        out = out.replace(old, new)
    return out
