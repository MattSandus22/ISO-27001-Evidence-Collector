"""Command-line interface: iso27k collect | ingest | verify | assess | list-checks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .assess import load_controls, run_checks, summarize_controls
from .checks import REGISTRY
from .evidence import IntegrityError, load_evidence, save_snapshot, verify
from .models import ControlStatus
from .report import RENDERERS


def cmd_collect(args: argparse.Namespace) -> int:
    if args.source == "github":
        from .collectors.github import GitHubCollector

        token = os.environ.get(args.token_env)
        if not token:
            print(f"error: set {args.token_env} to a GitHub token", file=sys.stderr)
            return 2
        snapshot = GitHubCollector(token, org=args.org).collect()
    else:
        from .collectors.aws import AWSCollector

        import boto3

        session = boto3.Session(profile_name=args.profile) if args.profile else None
        regions = [r.strip() for r in args.regions.split(",")] if args.regions else None
        snapshot = AWSCollector(session=session, regions=regions).collect()
    path = save_snapshot(snapshot, args.out)
    print(f"Saved {snapshot['source']} evidence for {snapshot.get('scope')} -> {path}")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    snapshot = json.loads(Path(args.file).read_text())
    path = save_snapshot(snapshot, args.out)
    print(f"Ingested {args.file} -> {path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    results = verify(args.evidence)
    if not results:
        print("No manifest entries found.", file=sys.stderr)
        return 2
    for name, ok in results:
        print(f"{'OK      ' if ok else 'TAMPERED'}  {name}")
    return 0 if all(ok for _, ok in results) else 1


def cmd_assess(args: argparse.Namespace) -> int:
    try:
        snapshots, manifest = load_evidence(args.evidence)
    except (FileNotFoundError, IntegrityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings = run_checks(snapshots)
    controls = summarize_controls(findings, load_controls())
    output = RENDERERS[args.format](controls, findings, manifest)
    if args.output:
        Path(args.output).write_text(output)
        print(f"Wrote {args.format} report -> {args.output}")
    else:
        sys.stdout.write(output)
    gaps = [c for c in controls if c.status == ControlStatus.GAP]
    return 1 if args.fail_on_gap and gaps else 0


def cmd_list_checks(_: argparse.Namespace) -> int:
    for c in REGISTRY.values():
        print(f"{c.id:8} {c.source:7} A.{', A.'.join(c.controls):18} {c.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iso27k", description="ISO/IEC 27001:2022 technical evidence collector")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="collect live evidence (read-only API calls)")
    c.add_argument("source", choices=["github", "aws"])
    c.add_argument("--out", default="evidence", help="evidence directory (default: evidence)")
    c.add_argument("--org", help="GitHub organization (omit to scan your own repos)")
    c.add_argument("--token-env", default="GITHUB_TOKEN", help="env var holding the GitHub token")
    c.add_argument("--profile", help="AWS profile name")
    c.add_argument("--regions", help="comma-separated AWS regions (default: profile region)")
    c.set_defaults(func=cmd_collect)

    i = sub.add_parser("ingest", help="add an existing snapshot JSON to the evidence store")
    i.add_argument("file")
    i.add_argument("--out", default="evidence")
    i.set_defaults(func=cmd_ingest)

    v = sub.add_parser("verify", help="check evidence files against their recorded SHA-256 hashes")
    v.add_argument("evidence")
    v.set_defaults(func=cmd_verify)

    a = sub.add_parser("assess", help="run checks and produce a report")
    a.add_argument("evidence")
    a.add_argument("--format", choices=sorted(RENDERERS), default="md")
    a.add_argument("-o", "--output", help="write report to a file instead of stdout")
    a.add_argument("--fail-on-gap", action="store_true", help="exit 1 if any control has a gap (for CI)")
    a.set_defaults(func=cmd_assess)

    lc = sub.add_parser("list-checks", help="show every check and its Annex A mapping")
    lc.set_defaults(func=cmd_list_checks)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
