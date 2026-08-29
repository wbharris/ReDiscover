# ReDiscover™

Kali **recon** as one engagement case: whois, DNS, subdomains, what actually ran.

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
rediscover recon example.com --json
rediscover recon example.com --offline
rediscover recon example.com --dry-run
```

| Flag | Meaning |
|------|---------|
| `--company` | Organization name on the report |
| `--offline` | Do not call whois/DNS/subdomain tools; still write the case |
| `--dry-run` | Print the tool plan; do not execute |
| `--json` | Case file instead of markdown |
| `-o` | Write to a file (default: stdout) |

`--offline` skips **live** lookups only. The case, honesty layer, and report still run.

Passive uses whatever is already installed: `whois`, `dig` (or `host`), and when present `subfinder`, `amass`, `sublist3r`. Missing tools are skipped and named.

## What you get

A markdown report (or `--json` case):

1. Engagement summary
2. Domain identity
3. DNS
4. Hosts / subdomains
5. People and emails
6. Sources (commands)
7. Confidence and what would improve this

## Trademark

**ReDiscover™** is a trademark of wbharris. See [`TRADEMARK.md`](TRADEMARK.md).
The GPL covers the code, not the name. Do not use `®` until a registration issues.

## License

Copyright (C) 2026 wbharris

[GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later).
