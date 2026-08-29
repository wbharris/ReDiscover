# ReDiscover™

A **Grok skill** plus a small CLI that **runs [Lee Baird’s Discover](https://github.com/leebaird/discover) on Kali Purple and corrects the failures we hit**, and still writes one **engagement case**.

Not a Discover fork. Discover stays the bash menu and HTML tree at `/opt/discover`. ReDiscover is `doctor` + `recon` + `person` + `enrich`. No Metasploit payloads or listeners.

Repo: https://github.com/wbharris/ReDiscover

Full contract: [`docs/PRODUCT.md`](docs/PRODUCT.md). Agent loop: [`.grok/skills/rediscover/SKILL.md`](.grok/skills/rediscover/SKILL.md). Credits: [`CREDITS.md`](CREDITS.md).

**Use only on assets you are allowed to test.**

## Direction

The skill is the operator. The CLI is the case file.

1. **Shepherd Discover** — diagnose Update/install breakage (`rediscover doctor`), `--fix` it, then run option 18 as `sudo /opt/discover/misc/update.sh`. Do **not** type Discover’s numbered menu over a pipe.
2. **When Discover recon is the job** — call the scripts with `DISCOVER_SOURCE_ONLY=1` (Passive cannot be root; Active needs a Passive report; Scanning is nmap, not Domain → Active).
3. **When one case file is the job** — `rediscover recon` / `enrich` / `person`. That is ReDiscover’s report, not `$HOME/data/DOMAIN` HTML.
4. **Stay honest** — missing tools are skipped and named; new enrich hosts stay unconfirmed; lab fiction is not people-OSINT.

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

ReDiscover `--active` is httpx/whatweb (optional nmap **top 20**). That is **not** Discover Domain → Active (gowitness) and **not** Discover Scanning (`-p-` + UDP).

Authorized first-test labs only:

| Target | Use for | Do not |
|--------|---------|--------|
| `example.com` | DNS/whois/enrich smoke | nmap |
| `ginandjuice.shop` | Passive + Active web (PortSwigger invited scanners) | `portswigger.net`; `ginandjuice.com` / `.mx` |
| `scanme.nmap.org` | Active nmap (Fyodor’s public grant) | `nmap.org` or other Nmap hosts |

There is no SANS public recon student host. **Do not scan `sans.org` / `sans.edu`.**

```bash
BIN=./.venv/bin/rediscover
export PATH="/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:$HOME/theHarvester/.venv/bin"

$BIN recon example.com --quick --enrich
$BIN recon ginandjuice.shop --quick --enrich --active --max-hosts 1
$BIN recon scanme.nmap.org --quick --active --max-hosts 1 --nmap
$BIN enrich TARGET
$BIN person Jane Doe
```

`--enrich` is crt.sh, GitHub, and the homepage. New names stay **unconfirmed**. It does not call Brave/Google/Bing. Search-engine-shaped queries after that are a Grok `web_search` pass, merged as `grok-public`, still unconfirmed.

Whois that is retired (`.shop`) or malformed (a hostname like `scanme.nmap.org`) falls back to **RDAP**. theHarvester’s author banner is not a target email.

## CLI flags

```bash
rediscover recon example.com --company 'Example Inc' -o report.md
rediscover recon example.com --quick --active --nmap --max-hosts 10 --json
rediscover recon example.com --offline
rediscover recon example.com --dry-run --active --nmap
rediscover person Jane Doe --open
rediscover doctor
sudo rediscover doctor --fix
```

| Flag | Meaning |
|------|---------|
| `--company` | Organization name on the report |
| `--offline` | Do not call whois/DNS/subdomain tools; still write the case |
| `--dry-run` | Print the tool plan; do not execute |
| `--quick` | Skip amass, sublist3r, and dnstwist |
| `--enrich` | crt.sh + GitHub + homepage; new names stay **unconfirmed** |
| `--active` | Resolve public hosts and HTTP-probe them |
| `--nmap` | Also `nmap -sV --top-ports 20` on public IPs (requires `--active`) |
| `--max-hosts` | Cap active HTTP/nmap hosts (default 25) |
| `--json` | Case file instead of markdown |
| `-o` | Write to a file (default: stdout) |
| `--open` | (`person` only) open search URLs in Firefox |

`--offline` skips **live** lookups only. The case, honesty layer, and report still run. Missing tools are skipped and named.

Local cases belong under `cases/` (gitignored). Discover HTML stays under `$HOME/data/`.

## What you get (ReDiscover case)

1. Engagement summary
2. Domain identity (or person search URLs)
3. DNS
4. Hosts / subdomains (HTTP status when `--active`)
5. People and emails
6. Lookalike domains
7. Sources (commands)
8. Confidence and what would improve this

## Trademark

**ReDiscover™** is a trademark of wbharris. See [`TRADEMARK.md`](TRADEMARK.md).
The GPL covers the code, not the name. Do not use `®` until a registration issues.

## License

Copyright (C) 2026 wbharris

[GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later).
