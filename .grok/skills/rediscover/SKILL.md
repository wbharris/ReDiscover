---
name: rediscover
description: >
  Recon case from the tools installed on this box, plus Discover doctor on
  Kali Purple. Use when the user says ReDiscover, rediscover recon,
  rediscover tools, Discover option 18, update.sh, arp-scan/questing,
  snap Metasploit, dubious ownership, sudo secure_path, or /rediscover.
argument-hint: "[tools | recon DOMAIN | doctor --fix | enrich DOMAIN|CASE.json | person FIRST LAST]"
---

ReDiscover™ writes one recon case from the tools already installed on this box (`rediscover tools`, `rediscover recon`). It also shepherds [Lee Baird’s Discover](https://github.com/leebaird/discover). Product: `docs/PRODUCT.md` in https://github.com/wbharris/ReDiscover. Discover clone: `/opt/discover`. CLI: `/home/iceroot/Projects/ReDiscover/.venv/bin/rediscover` (`rediscover` is not on iceroot PATH). Do not install recon tools from the agent unless the operator asks. Do not add nuclei, wordlist brute force, payloads, listeners, or an autonomous attack agent.

Do not drive Discover’s numbered menu over stdin. Option 18 is `sudo /opt/discover/misc/update.sh` after doctor. Recon is `rediscover recon`. Run recon as **iceroot**, not root.

## Default loop (Discover Update)

When the user wants Discover to work, or pastes an Update log:

1. `rediscover doctor --json` (venv path above).
2. If any check is `"ok": false`, run `sudo rediscover doctor --fix` (root for apt, sudoers, venvs).
3. Re-run `rediscover doctor --json` and report FAIL vs fixed.
4. Only then run Update if they asked: `sudo /opt/discover/misc/update.sh`.
5. If the log still shows `arp-scan/questing`, `snap: command not found`, `dubious ownership`, or `No module named pip`, go back to step 2. `git pull` can wipe the Kali `update.sh` patch; doctor reapplies it.

## What doctor fixes

| id | Repair |
|----|--------|
| `discover-git` | `safe.directory` + chown `/opt/discover` to the operator |
| `wrapper` | `/usr/local/bin/discover` → `/opt/discover/discover.sh` |
| `arp-scan` | `apt install arp-scan` (not `/questing`) |
| `update-sh-kali` | Patch `misc/update.sh` for Kali arp-scan + apt Metasploit |
| `sudo-secure-path` | `/etc/sudoers.d/rediscover` adds `/usr/local/bin` (stops “Installing gowitness” every run) |
| `libpostal-data` | `libpostal_data download` so Kali amass does not sudo |
| `uv-path` | Symlink `~/.local/bin/uv` → `/usr/local/bin/uv` |
| `active-sh-loopback` | Patch Discover `active.sh` to skip 127.0.0.1 / 169.254 |
| `sudo-nmap` | Operator NOPASSWD `/usr/bin/nmap` (Discover Scanning) |
| `dnsrecon-venv` / `sublist3r-venv` | Recreate venv so `python -m pip` works after a Python upgrade |

Do not install snapd for Metasploit on Kali. Apt `metasploit-framework` is the package.

## Recon

Authorized targets only. Prefer iceroot. PATH for Discover/ReDiscover recon:

`/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:$HOME/theHarvester/.venv/bin`

`/usr/local/bin` before Python venvs so ProjectDiscovery `httpx` wins over `/usr/bin/httpx` (Python). `$HOME/.local/bin` is **uv** (Discover Passive `uv sync`). theHarvester CLI is in `~/theHarvester/.venv/bin`.

```bash
BIN=/home/iceroot/Projects/ReDiscover/.venv/bin/rediscover
PATH="/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:$HOME/theHarvester/.venv/bin"

$BIN tools
$BIN recon example.com --quick --passive
$BIN recon ginandjuice.shop --quick --no-ports --max-hosts 1
$BIN recon scanme.nmap.org --quick --max-hosts 1
$BIN enrich TARGET
$BIN enrich case.json --json -o case.json
$BIN person First Last
```

Write cases to `ReDiscover/cases/` (`--json` plus markdown). `cases/` is gitignored.

### Legal first-test labs (do not invent others)

| Target | Use for | Do not |
|--------|---------|--------|
| `example.com` | `--passive` DNS/whois/enrich smoke | default `recon` (it port-scans); nmap |
| `ginandjuice.shop` | `--no-ports --max-hosts 1` web probe | nmap; theHarvester/nmap on `portswigger.net`; do not add `ginandjuice.com` / `.mx` |
| `scanme.nmap.org` | `recon --max-hosts 1` (Fyodor’s public grant) | HTTP/nmap `nmap.org` or other Nmap hosts |

There is **no** SANS public recon student host. **Do not scan `sans.org` / `sans.edu`.**

`rediscover recon DOMAIN` is the single pane. It runs the roster, then crt.sh, GitHub, and the homepage, then resolves and probes the merged host list, and writes one case. Missing binaries are skipped. It does not install them.

Passive host tools: subfinder (`-all` unless `--quick`), assetfinder, findomain, and (unless `--quick`) amass, sublist3r, and chaos. Chaos runs only when `CHAOS_KEY` or `PDCP_API_KEY` is set. `--quick` also skips dnstwist, gau, waybackurls, and urlfinder. Those URL tools store at most 200 in-scope URLs and do not fetch them.

Probes are on by default: dnsx (or dig/host), httpx, whatweb (`--quiet --no-errors --log-json=-`), tlsx, naabu, and nmap top 20. tlsx names stay unconfirmed and are not probed again in that run. `--passive` skips those connections. `--no-ports` keeps HTTP and skips naabu and nmap. `--max-hosts 1` is the light first pass. Do not run a default recon against `example.com` or `ginandjuice.shop`; those labs use `--passive` and `--no-ports`. Do not add nuclei, puredns, shuffledns, alterx, katana, or uncover.

Kali naabu 2.6.1 accepts `-top-ports` only as `100`, `1000`, or `full`. ReDiscover passes `-p` with the same 20 ports as `nmap --top-ports 20`, plus `-duc -no-stdin`. Open nmap ports are copied onto `Host.ports`. subfinder writes its host list only after sources finish, so the argv includes `-duc` and `-max-time` (1 minute on `--quick`, 2 on a full run) inside the process timeout. crt.sh HTTP 502 stays a recorded failure. Chaos still needs `CHAOS_KEY` or `PDCP_API_KEY`.

### Enrich

A normal `recon` already queries **crt.sh**, **GitHub** (PAT from `GITHUB_TOKEN` or `~/.theHarvester/api-keys.yaml`), and the **site homepage** before the probe. New hosts/emails stay `unconfirmed`. `--no-enrich` skips that step. It does **not** call Brave/Google/Bing.

If the operator wants search-engine-shaped queries after that, use Grok `web_search` on `"DOMAIN"` and `site:DOMAIN`, merge as source `grok-public`, keep **unconfirmed**. Do not invent hosts. Do not treat lab fiction (e.g. Carlos Montoya on the shop) as people-OSINT.

crt.sh often **502**s; say so, do not retry in a loop.

### Discover Passive / Active / Scanning (not the numbered menu)

Use `DISCOVER_SOURCE_ONLY=1` and the scripts. Do **not** pipe choices into `discover.sh`.

```bash
export DISCOVER_SOURCE_ONLY=1 HOME=/home/iceroot
export PATH="/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:$HOME/theHarvester/.venv/bin"
source /opt/discover/discover.sh

# Domain → Passive (cannot be root)
printf '%s\n%s\n' "Company" "ginandjuice.shop" | /opt/discover/recon/passive.sh
# then Active (needs $HOME/data/DOMAIN from Passive)
DISCOVER_REPORT="$HOME/data/ginandjuice.shop" /opt/discover/recon/active.sh

# Scanning → IP (nmap.sh). sudo nmap: doctor --fix grants NOPASSWD nmap, or run this as root.
# Answers: External, scan name, target, full TCP y, -sV y, delay 1, MSF aux n
```

Kali `/usr/bin/amass` is a wrapper that `sudo libpostal_data download` if `/usr/share/libpostal/transliteration` is missing. `doctor --fix` installs that data so Passive Amass does not prompt.

Discover Active’s Python `is_private_ip` used to skip only RFC1918. `test.ginandjuice.shop → 127.0.0.1` was queued as public. `doctor --fix` patches `recon/active.sh` (loopback + link-local). `git pull` can wipe it; doctor reapplies.

### Honesty from live labs

- Classic **whois** is retired on some TLDs (`.shop`) and **malformed** on hostnames (`scanme.nmap.org`). ReDiscover then queries **RDAP**. Parent-zone RDAP is registry identity, not a scan of the parent’s other hosts.
- Ignore `cmartorella@edge-security.com` — that is theHarvester’s **author banner**, not a target contact. “No emails found” means none.
- `test.ginandjuice.shop` → `127.0.0.1` is not a public host; `--active` must skip loopback.
- Passive Discover (`./discover.sh`) cannot run as root.

## After a doctor/update run

Tell the operator which checks were FAIL, which `--fix` changed, and whether Update is safe to run again. Link upstream bug if still relevant: https://github.com/leebaird/discover/issues/227
