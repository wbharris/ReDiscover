# ReDiscover™ product contract

End goal: one **engagement case** for an authorized domain or person, filled from the recon tools installed on the box. The CLI also runs Discover on Kali Purple and corrects the failures we hit.

ReDiscover does **not** replace [Lee Baird’s Discover](https://github.com/leebaird/discover). `doctor` shepherds that clone (`/opt/discover`). The case file is ReDiscover’s own report, in the same family as VulNavigator™. Discover stays the bash menu + HTML tree. ReDiscover is `tools` + `recon` + `enrich` + `person` + `doctor`.

Repo: https://github.com/wbharris/ReDiscover

**ReDiscover™** is a trademark of wbharris (common-law ™, not a registered ®). See [`TRADEMARK.md`](../TRADEMARK.md).

Inspired by Discover (MIT). ReDiscover is original GPL-3.0-or-later work. See [`CREDITS.md`](../CREDITS.md).

## Why this exists

Discover on this workstation lives at `/opt/discover` (clone of `leebaird/discover`). Upstream is still active. The pain is not “the GitHub repo is dead.” It is:

- Menu-driven bash, hard to test, hard to automate
- HTML report tree instead of a single case you can pipe elsewhere
- Kitchen-sink extras (msfvenom payloads, listeners) mixed with recon
- Tool failures are easy to miss in a 66-step passive run

ReDiscover keeps the recon job and drops the rest.

## Authorized use

Only against assets you are allowed to test. Passive DNS/whois is still third-party data collection. Active probes (HTTP fingerprinting, top ports) need a written OK. Person recon emits **search URLs**; it does not scrape broker sites or claim a match. ReDiscover will not generate Metasploit payloads, start listeners, run nuclei or other exploit templates, brute-force paths or logins, or start an autonomous attack agent.

## User journey

```
domain | person
              │
              ▼
        1. Intake
              │
              ▼
        2. One recon
     roster · enrich · resolve · HTTP · top ports
     every name merged onto one host list
              │
              ▼
        3. Case report
     summary · identity · DNS · hosts
     people · lookalikes · URLs · sources · gaps
              │
              ▼
        4. Honesty layer
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
| Whois | `whois`; **RDAP** (`rdap.org`) when whois is retired, malformed, or missing |
| DNS | `dig` (fallback `host`) — A, AAAA, MX, NS, TXT, SOA, CNAME |
| Subdomains | `subfinder -all -silent -duc -max-time 2` (`--quick` drops `-all` and uses `-max-time 1`), `assetfinder --subs-only`, `findomain -t -q`, `amass enum -passive`, `sublist3r`, `chaos -d -silent` when `CHAOS_KEY` or `PDCP_API_KEY` is set |
| Archive URLs | `gau --subs`, `waybackurls` (domain on stdin), `urlfinder -d -silent`. In-scope `http`/`https` only, capped at 200. Nothing is fetched |
| Squatting | `dnstwist -r -f json` |
| People / mail | whois emails; `theHarvester -b duckduckgo` when present (ignore the tool banner address) |

`rediscover recon DOMAIN` runs that roster, then crt.sh / GitHub / the homepage, then resolves and probes the merged host list. One case comes back. Missing tools are skipped and named. `rediscover tools` lists the roster. It does not install anything.

`--passive` skips HTTP probes, tlsx, naabu, and nmap. Enrich still runs. `--no-ports` keeps the HTTP probe and skips naabu and nmap. `--no-enrich` skips crt.sh, GitHub, and the homepage. `--quick` skips amass, sublist3r, dnstwist, chaos, gau, waybackurls, and urlfinder, and runs subfinder without `-all`. `--offline` writes the skeleton and does not call the roster.

The check does not include nuclei, wordlist brute force (`puredns`, `shuffledns`, `alterx`), a live crawler (`katana`), or search-engine host dumps (`uncover`).

### 3. Probes in the same recon

On by default. Needs authorization. `--passive` turns this step off.

| Step | Tools |
|------|-------|
| Resolve | `dnsx -silent -a -resp` (hosts on stdin) when it is installed; otherwise `dig` / `host` A records |
| HTTP | ProjectDiscovery `httpx` JSON (ELF; not Python `httpx`). Fallback `curl` |
| Fingerprint | `whatweb` when URLs are alive |
| Certificates | `tlsx -silent -dns` on the probed hosts. In-scope names are added unconfirmed, capped at 50, and are not probed again in that run |
| Ports | `naabu -silent -duc -no-stdin -p <nmap top 20> -rate 200` when installed, then `nmap -Pn -sV --top-ports 20`. This Kali naabu accepts `-top-ports` only as `100`, `1000`, or `full`. Open ports from nmap text are copied onto the host. `--no-ports` skips both |

Enrich runs first, so certificate and homepage names are on the list that gets probed. New enrich names stay `unconfirmed`. RFC1918 / loopback / link-local hosts are not probed. `--max-hosts` caps HTTP and port scans (default 25). Archive URLs are not a crawl. `--nmap` with `--passive`, or `--nmap` with `--offline` and without `--active`, is an error.

### 4. Person recon

`rediscover person FIRST LAST` writes search URLs (DuckDuckGo, Google, LinkedIn, GitHub, Wikipedia, YouTube, Facebook public, plus the people-search pages Discover used). `--open` launches Firefox (or `xdg-open`). `--open` does not scrape those sites.

### 5. Case report

Markdown (default) or `--json`.

Domain: summary, identity, DNS, hosts (including HTTP and ports), contacts, lookalikes, historical URLs, sources, honesty, nmap if run.

Person: summary, search URLs, sources, honesty.

### 6. Honesty layer

Every tool is `ran`, `skipped`, or `failed` with a reason. Guessed fields are listed. Counts in the summary must match the lists.

## Doctor

1. `rediscover doctor --json`
2. `sudo rediscover doctor --fix` if anything FAIL
3. `sudo /opt/discover/misc/update.sh` only when the operator asked for Discover Update (menu 18)

`doctor --fix` repairs: git `safe.directory` / ownership, `/usr/local/bin/discover`, Kali `arp-scan`, Kali `update.sh` (arp-scan + apt Metasploit), sudo `secure_path` and NOPASSWD nmap (`/etc/sudoers.d/rediscover`), libpostal data (amass wrapper), `uv` on `/usr/local/bin`, Discover Active loopback skip, DNSRecon/Sublist3r venvs. Upstream: https://github.com/leebaird/discover/issues/227

## What v0.6 is

- `rediscover recon DOMAIN` — one pass: roster, enrich, resolve, HTTP, top-20 ports, one case
- `--passive` — same case without HTTP, naabu, or nmap
- `--no-ports` — HTTP probe, no naabu or nmap
- `--quick` — skips the slow passive tools; probes still run
- `rediscover tools` — installed vs missing
- `rediscover enrich` — crt.sh, GitHub PAT, homepage into an existing case
- `rediscover person FIRST LAST` — search URLs
- `rediscover doctor [--fix]` for the Discover clone

## What v0.6 is not

- A Discover fork or HTML report clone
- Payloads, listeners, nuclei, wordlist brute force, or an autonomous attack agent
- A tool installer (`tools` only reports)
- A replacement for SpiderFoot / Maltego
- Unauthenticated scanning of the public internet as a service
- Confirmed identity from a name search
