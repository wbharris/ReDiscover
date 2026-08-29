# ReDiscover™ product contract

End goal: an operator gives ReDiscover a **domain** or a **person** and gets one **engagement case** they can act on — assets, DNS, contacts, search URLs, what ran, and what is still missing.

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

Only against assets you are allowed to test. Passive DNS/whois is still third-party data collection. Active probes (HTTP fingerprinting, nmap) need a written OK. Person recon emits **search URLs**; it does not scrape broker sites or claim a match. ReDiscover will not generate Metasploit payloads or start listeners.

## User journey

```
domain | person
              │
              ▼
        1. Intake
              │
              ▼
        2. Passive recon          person: search URLs
     whois · DNS · subdomains
     contacts · dnstwist
              │
              ▼
        3. Active recon (opt-in)
     resolve · HTTP probe · nmap when asked
              │
              ▼
        4. Case report
     summary · identity · DNS · hosts
     people · lookalikes · sources · gaps
              │
              ▼
        5. Honesty layer
     tools ran / skipped / failed
     assumptions · what would improve this
```

VulNavigator sits **after** a finding exists. ReDiscover sits **before**. A later handoff (hosts + software → `vuln-nav`) is allowed; it is not required.

### 1. Intake

| Source | What we accept |
|--------|----------------|
| **Domain** | `example.com` |
| **Person** | First + last name (`rediscover person FIRST LAST`) |
| **Host list / CIDR** | Later |

Unknown flags error. Empty domain or junk names are rejected.

### 2. Passive recon

Use tools **already on the box**. Missing tools are skipped and named, not treated as a crash.

| Check | Tools (when present) |
|-------|----------------------|
| Whois | `whois` |
| DNS | `dig` (fallback `host`) — A, AAAA, MX, NS, TXT, SOA, CNAME |
| Subdomains | `subfinder`, `amass` (`enum -passive`), `sublist3r` |
| Squatting | `dnstwist -r -f json` |
| People / mail | whois emails; `theHarvester -b duckduckgo` when present |

`--offline` skips live lookups and still writes the case skeleton.

`--quick` skips amass, sublist3r, and dnstwist (whois + DNS + subfinder + theHarvester still run).

### 3. Active recon

Opt-in (`--active`). Needs authorization.

| Step | Tools |
|------|-------|
| Resolve | `dig` / `host` A records |
| HTTP | `httpx` JSON (fallback `curl`) |
| Fingerprint | `whatweb` when URLs are alive |
| Ports | `nmap -Pn -sV --top-ports 20` only with `--nmap` |

RFC1918 / loopback / link-local hosts are not probed. `--max-hosts` caps HTTP/nmap (default 25). `--nmap` without `--active` is an error.

### 4. Person recon

`rediscover person FIRST LAST` writes search URLs (DuckDuckGo, Google, LinkedIn, GitHub, Wikipedia, YouTube, Facebook public, plus the people-search pages Discover used). `--open` launches Firefox (or `xdg-open`). `--open` does not scrape those sites.

### 5. Case report

Markdown (default) or `--json`.

Domain: summary, identity, DNS, hosts (including HTTP), contacts, lookalikes, sources, honesty, nmap if run.

Person: summary, search URLs, sources, honesty.

### 6. Honesty layer

Every tool is `ran`, `skipped`, or `failed` with a reason. Guessed fields are listed. Counts in the summary must match the lists.

## What v0.2 is

- `rediscover recon DOMAIN` — live passive
- `rediscover recon DOMAIN --active` — plus HTTP
- `rediscover recon DOMAIN --active --nmap` — plus nmap
- `rediscover person FIRST LAST` — search URLs

## What v0.2 is not

- A Discover fork or HTML report clone
- Payloads, listeners, or exploit wrappers
- A replacement for SpiderFoot / Maltego
- Unauthenticated scanning of the public internet as a service
- Confirmed identity from a name search
