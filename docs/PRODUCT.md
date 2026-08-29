# ReDiscover™ product contract

End goal: an operator gives ReDiscover a **domain** (later: host list, CIDR, or person) and gets one **engagement case** they can act on — assets, DNS, contacts, what ran, and what is still missing.

ReDiscover does **not** replace [Lee Baird’s Discover](https://github.com/leebaird/discover). It sits in the same job: Kali recon. Discover is a long bash menu that shells out to other tools and writes an HTML tree under `$HOME/data/<domain>/`. ReDiscover is a **CLI case file** in the same family as VulNavigator™: normalize, run, report, stay honest.

Repo: https://github.com/wbharris/ReDiscover

**ReDiscover™** is a trademark of wbharris (common-law ™, not a registered ®). See [`TRADEMARK.md`](../TRADEMARK.md).

Inspired by Discover (MIT). ReDiscover is original GPL-3.0-or-later work. See [`CREDITS.md`](../CREDITS.md).

## Why this exists

Discover on this workstation lives at `/root/discover` (clone of `leebaird/discover`, last local commit 2026-07-11). Upstream is still active. The pain is not “the GitHub repo is dead.” It is:

- Menu-driven bash, hard to test, hard to automate
- HTML report tree instead of a single case you can pipe elsewhere
- Kitchen-sink extras (msfvenom payloads, listeners) mixed with recon
- Tool failures are easy to miss in a 66-step passive run

ReDiscover keeps the recon job and drops the rest.

## Authorized use

Only against assets you are allowed to test. Passive DNS/whois is still third-party data collection. Active probes (port scans, HTTP fingerprinting, directory brute force) need a written OK. ReDiscover will not generate Metasploit payloads or start listeners.

## User journey

```
domain | host list | CIDR | person
              │
              ▼
        1. Intake
              │
              ▼
        2. Passive recon
     whois · DNS · subdomains · contacts
              │
              ▼
        3. Active recon (opt-in)
     resolve · HTTP probe · nmap when asked
              │
              ▼
        4. Case report
     summary · identity · DNS · hosts
     people · sources · gaps
              │
              ▼
        5. Honesty layer
     tools ran / skipped / failed
     assumptions · what would improve this
```

VulNavigator sits **after** a finding exists. ReDiscover sits **before**. A later handoff (hosts + software → `vuln-nav`) is allowed; it is not v0.1.

### 1. Intake

Any supported input becomes one **engagement**.

| Source | What we accept |
|--------|----------------|
| **Domain** | `example.com` (primary) |
| **Host list** | One hostname or IPv4 per line (later) |
| **CIDR** | Later |
| **Person** | First + last name (later; Discover menu 2) |

Unknown flags error. Empty domain is rejected.

### 2. Passive recon

Use tools **already on the box**. Missing tools are skipped and named, not treated as a crash.

| Check | Tools (when present) |
|-------|----------------------|
| Whois | `whois` |
| DNS | `dig` (fallback `host`) — A, AAAA, MX, NS, TXT, SOA, CNAME |
| Subdomains | `subfinder`, `amass` (`enum -passive`), `sublist3r` |
| Squatting | `dnstwist` (later) |
| People / mail | whois emails; theHarvester when present (later) |

`--offline` skips live lookups and still writes the case skeleton (same idea as VulNavigator `--offline`).

### 3. Active recon

Opt-in (`--active`). Not in v0.1 beyond a clear “not implemented” error. Planned: resolve public hosts, HTTP probe if `httpx`/`whatweb` exist, nmap only when the operator asks.

### 4. Case report

Markdown (default) or `--json`.

1. Engagement summary
2. Domain identity (whois)
3. DNS
4. Hosts / subdomains
5. People and emails
6. Sources (exact commands)
7. Confidence, assumptions, and what would improve this

### 5. Honesty layer

Every tool is `ran`, `skipped`, or `failed` with a reason. Guessed fields are listed. Counts in the summary must match the lists.

## What v0.1 is

`rediscover recon DOMAIN` — passive whois + DNS + optional subdomain tools, one report.

## What v0.1 is not

- A Discover fork or HTML report clone
- Payloads, listeners, or exploit wrappers
- A replacement for SpiderFoot / Maltego
- Unauthenticated scanning of the public internet as a service
