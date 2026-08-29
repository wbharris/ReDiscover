---
name: rediscover
description: >
  Run Discover on Kali Purple and correct Update/install failures via
  `rediscover doctor`. Use when the user says ReDiscover, Discover option 18,
  update.sh, arp-scan/questing, snap Metasploit, dubious ownership,
  sudo secure_path, or /rediscover.
argument-hint: "[doctor --fix | recon DOMAIN | enrich DOMAIN|CASE.json | person FIRST LAST]"
---

ReDiscover™ shepherds [Lee Baird’s Discover](https://github.com/leebaird/discover) on this box. Product: `docs/PRODUCT.md` in https://github.com/wbharris/ReDiscover. Discover clone: `/opt/discover`. CLI: `/home/iceroot/Projects/ReDiscover/.venv/bin/rediscover` (`rediscover` is not on iceroot PATH).

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
| `dnsrecon-venv` / `sublist3r-venv` | Recreate venv so `python -m pip` works after a Python upgrade |

Do not install snapd for Metasploit on Kali. Apt `metasploit-framework` is the package.

## Recon

Authorized targets only. Prefer iceroot. Put **`/usr/local/bin` before Python venvs** on PATH so ProjectDiscovery `httpx` wins over `/usr/bin/httpx` (Python). theHarvester lives at `~/theHarvester/.venv/bin` (CLI looks there).

```bash
BIN=/home/iceroot/Projects/ReDiscover/.venv/bin/rediscover
PATH="/usr/local/bin:/usr/bin:/bin:$HOME/theHarvester/.venv/bin"

$BIN recon example.com --quick --enrich
$BIN recon ginandjuice.shop --quick --enrich --active --max-hosts 1
$BIN recon scanme.nmap.org --quick --active --max-hosts 1 --nmap
$BIN enrich TARGET
$BIN enrich case.json --json -o case.json
$BIN person First Last
```

Write cases to `ReDiscover/cases/` (`--json` plus markdown). `cases/` is gitignored.

### Legal first-test labs (do not invent others)

| Target | Use for | Do not |
|--------|---------|--------|
| `example.com` | DNS/whois/enrich smoke | nmap |
| `ginandjuice.shop` | Passive + light Active web (PortSwigger invited scanners) | theHarvester/nmap on `portswigger.net`; do not add `ginandjuice.com` / `.mx` |
| `scanme.nmap.org` | `--active --nmap` (Fyodor’s public grant) | HTTP/nmap `nmap.org` or other Nmap hosts |

There is **no** SANS public recon student host. **Do not scan `sans.org` / `sans.edu`.**

`--quick` skips amass, sublist3r, dnstwist. `--nmap` requires `--active`. `--max-hosts 1` is the light first pass.

### Enrich

`--enrich` queries **crt.sh**, **GitHub** (PAT from `GITHUB_TOKEN` or `~/.theHarvester/api-keys.yaml`), and the **site homepage**. New hosts/emails are `unconfirmed`. It does **not** call Brave/Google/Bing.

If the operator wants search-engine-shaped queries after that, use Grok `web_search` on `"DOMAIN"` and `site:DOMAIN`, merge as source `grok-public`, keep **unconfirmed**. Do not invent hosts. Do not treat lab fiction (e.g. Carlos Montoya on the shop) as people-OSINT.

crt.sh often **502**s; say so, do not retry in a loop.

### Honesty from live labs

- Classic **whois** is retired on some TLDs (`.shop`) and **malformed** on hostnames (`scanme.nmap.org`). ReDiscover then queries **RDAP**. Parent-zone RDAP is registry identity, not a scan of the parent’s other hosts.
- Ignore `cmartorella@edge-security.com` — that is theHarvester’s **author banner**, not a target contact. “No emails found” means none.
- `test.ginandjuice.shop` → `127.0.0.1` is not a public host; `--active` must skip loopback.
- Passive Discover (`./discover.sh`) cannot run as root.

## After a doctor/update run

Tell the operator which checks were FAIL, which `--fix` changed, and whether Update is safe to run again. Link upstream bug if still relevant: https://github.com/leebaird/discover/issues/227
