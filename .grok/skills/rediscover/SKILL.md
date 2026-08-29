---
name: rediscover
description: >
  Run Discover on Kali Purple and correct Update/install failures via
  `rediscover doctor`. Use when the user says ReDiscover, Discover option 18,
  update.sh, arp-scan/questing, snap Metasploit, dubious ownership,
  sudo secure_path, or /rediscover.
argument-hint: "[doctor --fix | recon DOMAIN | enrich DOMAIN|CASE.json | person FIRST LAST]"
---

ReDiscover™ shepherds [Lee Baird’s Discover](https://github.com/leebaird/discover) on this box. Product: `docs/PRODUCT.md` in https://github.com/wbharris/ReDiscover. Discover clone: `/opt/discover`.

Do not drive Discover’s numbered menu over stdin. Option 18 is `sudo /opt/discover/misc/update.sh` after doctor. Recon is `rediscover recon`.

## Default loop

When the user wants Discover to work, or pastes an Update log:

1. `rediscover doctor --json` (from the ReDiscover venv if needed: `/home/iceroot/Projects/ReDiscover/.venv/bin/rediscover`).
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

Authorized targets only.

```bash
rediscover recon example.com --quick
rediscover recon TARGET --quick --enrich
rediscover enrich TARGET
rediscover enrich case.json --json -o case.json
rediscover recon TARGET --active
rediscover person First Last
```

`enrich` / `--enrich` queries **crt.sh**, **GitHub** (PAT from `GITHUB_TOKEN` or `~/.theHarvester/api-keys.yaml`), and the **site homepage**. New hosts/emails are `unconfirmed`. It does **not** call Brave/Google/Bing or scrape their HTML.

If the operator wants search-engine-shaped queries after that, use Grok `web_search` on `"DOMAIN"` and `site:DOMAIN`, then merge candidates into the case with source `grok-public` and keep them unconfirmed. Do not invent hosts.

Passive Discover (`./discover.sh`) cannot run as root. Prefer iceroot.

## After a doctor/update run

Tell the operator which checks were FAIL, which `--fix` changed, and whether Update is safe to run again. Link upstream bug if still relevant: https://github.com/leebaird/discover/issues/227
