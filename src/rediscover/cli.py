"""CLI: rediscover recon DOMAIN | rediscover person FIRST LAST."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rediscover import __version__
from rediscover.doctor import apply_fixes, diagnose, to_markdown as doctor_markdown
from rediscover.pipeline import person, recon
from rediscover.report import to_json, to_markdown


def _emit(engagement, as_json: bool, output: str | None) -> int:
    text = to_json(engagement) if as_json else to_markdown(engagement)
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rediscover",
        description="ReDiscover™ — Kali recon into one engagement case.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=(
            f"ReDiscover™ {__version__} (rediscover)\n"
            "ReDiscover is a trademark of wbharris."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    rec = sub.add_parser("recon", help="Domain recon (passive, optional active)")
    rec.add_argument("domain", help="Target domain, e.g. example.com")
    rec.add_argument("--company", default="", help="Organization name on the report")
    rec.add_argument(
        "--offline",
        action="store_true",
        help="Skip live whois/DNS/subdomain lookups",
    )
    rec.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the tool plan without running it",
    )
    rec.add_argument(
        "--quick",
        action="store_true",
        help="Skip amass, sublist3r, and dnstwist",
    )
    rec.add_argument(
        "--active",
        action="store_true",
        help="Resolve public hosts and HTTP-probe them",
    )
    rec.add_argument(
        "--nmap",
        action="store_true",
        help="Also nmap -sV --top-ports 20 on public IPs (requires --active)",
    )
    rec.add_argument(
        "--max-hosts",
        type=int,
        default=25,
        help="Cap active HTTP/nmap hosts (default: 25)",
    )
    rec.add_argument("--json", action="store_true", help="Write JSON instead of markdown")
    rec.add_argument("-o", "--output", help="Write report here (default: stdout)")

    per = sub.add_parser("person", help="Person recon (search URLs, optional --open)")
    per.add_argument("first", help="First name")
    per.add_argument("last", help="Last name")
    per.add_argument(
        "--open",
        action="store_true",
        dest="open_links",
        help="Open search URLs in Firefox (or xdg-open)",
    )
    per.add_argument("--dry-run", action="store_true", help="Show the open plan only")
    per.add_argument("--json", action="store_true", help="Write JSON instead of markdown")
    per.add_argument("-o", "--output", help="Write report here (default: stdout)")

    doc = sub.add_parser(
        "doctor",
        help="Diagnose Discover on Kali Purple; --fix applies repairs",
    )
    doc.add_argument(
        "--fix",
        action="store_true",
        help="Apply repairs (root for apt, sudoers, venvs)",
    )
    doc.add_argument("--json", action="store_true", help="Write JSON instead of markdown")
    doc.add_argument("-o", "--output", help="Write report here (default: stdout)")
    doc.add_argument(
        "--discover-root",
        default="/opt/discover",
        help="Discover clone (default: /opt/discover)",
    )

    args = parser.parse_args(argv)
    try:
        if args.cmd == "recon":
            if args.offline and args.dry_run:
                print("Use either --offline or --dry-run, not both.", file=sys.stderr)
                return 2
            if args.max_hosts < 1:
                print("--max-hosts must be >= 1", file=sys.stderr)
                return 2
            engagement = recon(
                args.domain,
                company=args.company,
                offline=args.offline,
                dry_run=args.dry_run,
                quick=args.quick,
                active=args.active,
                nmap=args.nmap,
                max_hosts=args.max_hosts,
            )
            return _emit(engagement, args.json, args.output)
        if args.cmd == "person":
            if args.dry_run and args.open_links:
                print("Use either --dry-run or --open, not both.", file=sys.stderr)
                return 2
            engagement = person(
                args.first,
                args.last,
                dry_run=args.dry_run,
                open_links=args.open_links,
            )
            return _emit(engagement, args.json, args.output)
        if args.cmd == "doctor":
            root = Path(args.discover_root)
            findings = diagnose(root)
            if args.fix:
                findings = apply_fixes(findings, root)
            if args.json:
                text = json.dumps([f.to_dict() for f in findings], indent=2) + "\n"
            else:
                text = doctor_markdown(findings)
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
            return 0 if all(f.ok for f in findings) else 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
