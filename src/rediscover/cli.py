"""CLI: rediscover recon DOMAIN."""

from __future__ import annotations

import argparse
import sys

from rediscover import __version__
from rediscover.pipeline import recon
from rediscover.report import to_json, to_markdown


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

    rec = sub.add_parser("recon", help="Passive recon for a domain")
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
    rec.add_argument("--json", action="store_true", help="Write JSON instead of markdown")
    rec.add_argument("-o", "--output", help="Write report here (default: stdout)")
    rec.add_argument(
        "--active",
        action="store_true",
        help="Active recon (not in v0.1)",
    )

    args = parser.parse_args(argv)
    if args.cmd != "recon":
        parser.error("unknown command")
    if args.active:
        print("ReDiscover v0.1 has no --active path yet. Use passive recon.", file=sys.stderr)
        return 2
    if args.offline and args.dry_run:
        print("Use either --offline or --dry-run, not both.", file=sys.stderr)
        return 2

    try:
        engagement = recon(
            args.domain,
            company=args.company,
            offline=args.offline,
            dry_run=args.dry_run,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = to_json(engagement) if args.json else to_markdown(engagement)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
