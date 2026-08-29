# ReDiscover™

Kali **recon** as one engagement case: whois, DNS, subdomains, HTTP, person search URLs, what actually ran.

Inspired by [Lee Baird’s Discover](https://github.com/leebaird/discover). Not a fork. No Metasploit payloads or listeners.

Repo: https://github.com/wbharris/ReDiscover

Full contract: [`docs/PRODUCT.md`](docs/PRODUCT.md). Credits: [`CREDITS.md`](CREDITS.md).

**Use only on assets you are allowed to test.**

## Install

```bash
git clone https://github.com/wbharris/ReDiscover.git
cd ReDiscover
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

## Use

```bash
rediscover recon example.com
rediscover recon example.com --company 'Example Inc' -o report.md
rediscover recon example.com --quick
rediscover recon example.com --quick --active
rediscover recon example.com --active --nmap --max-hosts 10
rediscover recon example.com --json
rediscover recon example.com --offline
rediscover recon example.com --dry-run --active --nmap
rediscover person Jane Doe
rediscover person Jane Doe --open
```

| Flag | Meaning |
|------|---------|
| `--company` | Organization name on the report |
| `--offline` | Do not call whois/DNS/subdomain tools; still write the case |
| `--dry-run` | Print the tool plan; do not execute |
| `--quick` | Skip amass, sublist3r, and dnstwist |
| `--active` | Resolve public hosts and HTTP-probe them |
| `--nmap` | Also `nmap -sV --top-ports 20` on public IPs (requires `--active`) |
| `--max-hosts` | Cap active HTTP/nmap hosts (default 25) |
| `--json` | Case file instead of markdown |
| `-o` | Write to a file (default: stdout) |
| `--open` | (`person` only) open search URLs in Firefox |

`--offline` skips **live** lookups only. The case, honesty layer, and report still run.

Passive uses whatever is already installed: `whois`, `dig` (or `host`), `subfinder`, `amass`, `sublist3r`, `dnstwist`, `theHarvester`. Active adds `httpx` (or `curl`), `whatweb`, and optional `nmap`. Missing tools are skipped and named.

## What you get

A markdown report (or `--json` case):

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
