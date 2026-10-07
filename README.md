# ReDiscover™

One recon command. It runs the tools already on the box (subfinder, assetfinder, findomain, amass, gau, dnsx, httpx, naabu, nmap, and the rest of the roster), pulls crt.sh, GitHub, and the homepage into the same host list, then writes one engagement file. Missing tools are skipped and named. `rediscover tools` shows what is installed. It does not install them.

It also shepherds [Lee Baird’s Discover](https://github.com/leebaird/discover) on Kali Purple (`rediscover doctor`). Discover stays the bash menu and HTML tree at `/opt/discover`. ReDiscover is `tools` + `recon` + `enrich` + `person` + `doctor`. No payloads, listeners, nuclei, or path brute force.

Repo: https://github.com/wbharris/ReDiscover

Full contract: [`docs/PRODUCT.md`](docs/PRODUCT.md). Agent loop: [`.grok/skills/rediscover/SKILL.md`](.grok/skills/rediscover/SKILL.md). Credits: [`CREDITS.md`](CREDITS.md).

**Use only on assets you are allowed to test.**

## Direction

The CLI is the recon case. The skill still doctors Discover.

1. **One recon** — `rediscover recon DOMAIN` runs the roster, enrich, and probes, and merges every name into one case. `--passive` skips HTTP and port scans. `rediscover tools` shows installed vs missing. It does not install tools, and it does not run exploit scanners.
2. **Shepherd Discover** — diagnose Update/install breakage (`rediscover doctor`), `--fix` it, then run option 18 as `sudo /opt/discover/misc/update.sh`. Do **not** type Discover’s numbered menu over a pipe.
3. **When Discover’s own HTML is the job** — call the scripts with `DISCOVER_SOURCE_ONLY=1` (Passive cannot be root; Active needs a Passive report; Scanning is nmap, not Domain → Active).
4. **Stay honest** — missing tools are skipped and named; archive URLs stay capped and unfetched; new enrich hosts stay unconfirmed; lab fiction is not people-OSINT.

Kali-specific repairs the skill expects `doctor --fix` to own: Ubuntu `arp-scan/questing`, snap Metasploit vs apt, git dubious ownership, sudo `secure_path` missing `/usr/local/bin`, Python 3.14 venvs without pip, Kali **amass** wrapping `sudo libpostal_data`, **uv** only in `~/.local/bin`, Discover Active treating `127.0.0.1` as public, operator password for `sudo nmap`. `git pull` can wipe the Discover-side patches; doctor reapplies them.

## Install

```bash
git clone https://github.com/wbharris/ReDiscover.git
cd ReDiscover
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Discover clone: `/opt/discover`. Operator recon as a normal user, not root.

PATH for both Discover scripts and ReDiscover:

```text
/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:$HOME/theHarvester/.venv/bin
```

`/usr/local/bin` first so ProjectDiscovery `httpx` wins over Python `/usr/bin/httpx`. `$HOME/.local/bin` is **uv** (Discover Passive `uv sync`).

## Doctor (Discover Update)

```bash
rediscover doctor --json
sudo rediscover doctor --fix
sudo /opt/discover/misc/update.sh
```

Grok: `/rediscover` — same loop. If the Update log still shows `arp-scan/questing`, `snap: command not found`, `dubious ownership`, or `No module named pip`, run `--fix` again.

## Recon

Two different jobs. Do not mix their outputs.

| Job | Command | Output |
|-----|---------|--------|
| ReDiscover case | `rediscover recon DOMAIN` | markdown / `--json` case |
| Discover Passive | `recon/passive.sh` as the operator | `$HOME/data/DOMAIN/` HTML |
| Discover Active | `recon/active.sh` after Passive | httpx, whatweb, **gowitness** into that report |
| Discover Scanning | `scan/nmap.sh` (full TCP/UDP) | nmap folder + `report.txt` |

`rediscover recon` resolves (dnsx or dig), probes with httpx, and runs naabu plus nmap on the **top 20** ports. `--passive` skips those connections. `--no-ports` keeps HTTP and skips the port scan. That is **not** Discover Domain → Active (gowitness) and **not** Discover Scanning (`-p-` + UDP).

Authorized first-test labs only:

| Target | Use for | Do not |
|--------|---------|--------|
| `example.com` | `--passive` (DNS, whois, enrich). No port scan | default `recon` (it includes nmap) |
| `ginandjuice.shop` | `--no-ports --max-hosts 1` (web probe, no nmap) | `portswigger.net`; `ginandjuice.com` / `.mx` |
| `scanme.nmap.org` | `recon` with `--max-hosts 1` (Fyodor’s public grant) | `nmap.org` or other Nmap hosts |

There is no SANS public recon student host. **Do not scan `sans.org` / `sans.edu`.**

```bash
BIN=./.venv/bin/rediscover
export PATH="/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:$HOME/theHarvester/.venv/bin"

$BIN tools
$BIN recon example.com --quick --passive
$BIN recon ginandjuice.shop --quick --no-ports --max-hosts 1
$BIN recon scanme.nmap.org --quick --max-hosts 1
$BIN enrich TARGET
$BIN person Jane Doe
```

`--enrich` is crt.sh, GitHub, and the homepage. New names stay **unconfirmed**. It does not call Brave/Google/Bing. Search-engine-shaped queries after that are a Grok `web_search` pass, merged as `grok-public`, still unconfirmed.

Whois that is retired (`.shop`) or malformed (a hostname like `scanme.nmap.org`) falls back to **RDAP**. theHarvester’s author banner is not a target email.

## CLI flags

```bash
rediscover tools
rediscover recon example.com --passive --company 'Example Inc' -o report.md
rediscover recon scanme.nmap.org --quick --max-hosts 1 --json
rediscover recon example.com --offline
rediscover recon example.com --dry-run
rediscover recon example.com --dry-run --passive
rediscover person Jane Doe --open
rediscover doctor
sudo rediscover doctor --fix
```

| Flag | Meaning |
|------|---------|
| `--company` | Organization name on the report |
| `--offline` | Do not call whois/DNS/subdomain tools; still write the case |
| `--dry-run` | Print the tool plan; do not execute |
| *(default)* | Roster + crt.sh/GitHub/homepage + resolve + HTTP + top-20 ports, one case |
| `--passive` | Skip HTTP probes, naabu, and nmap. Enrich still runs |
| `--no-ports` | Keep the HTTP probe. Skip naabu and nmap |
| `--no-enrich` | Skip crt.sh, GitHub, and the homepage |
| `--quick` | Skip amass, sublist3r, dnstwist, chaos, gau, waybackurls, and urlfinder. subfinder runs without `-all` and with `-max-time 1` |
| `--enrich` | With `--offline`, also run enrich. On a normal recon, enrich is already on |
| `--max-hosts` | Cap HTTP and port-scan hosts (default 25) |
| `--json` | Case file instead of markdown |
| `-o` | Write to a file (default: stdout) |
| `--open` | (`person` only) open search URLs in Firefox |

`--offline` skips **live** lookups only. The case, honesty layer, and report still run. Missing tools are skipped and named.

Local cases belong under `cases/` (gitignored). Discover HTML stays under `$HOME/data/`.

## What you get (ReDiscover case)

1. Engagement summary
2. Domain identity (or person search URLs)
3. DNS
4. Hosts / subdomains (HTTP status when `--active`, ports when `--nmap`)
5. People and emails
6. Lookalike domains
7. Historical URLs (capped; not fetched)
8. Sources (commands)
9. Confidence and what would improve this

## Trademark

**ReDiscover™** is a trademark of wbharris. See [`TRADEMARK.md`](TRADEMARK.md).
The GPL covers the code, not the name. Do not use `®` until a registration issues.

## License

Copyright (C) 2026 wbharris

[GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later).
