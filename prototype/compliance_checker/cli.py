"""Command line entry point: python -m compliance_checker scan ..."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .checks import run_checks
from .collectors import COLLECTORS
from .loader import load_controls
from .models import Status
from .report import print_report, write_json

DEFAULT_CONTROLS = Path(__file__).resolve().parent.parent / "controls" / "baseline.yaml"


# WHAT: Parse the command line, run collect -> check -> report, return an exit code.
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="compliance_checker",
                                description="Check a host against a security baseline.")
    sub = p.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan one target")
    scan.add_argument("--platform", choices=sorted(COLLECTORS), required=True)
    scan.add_argument("--source", required=True,
                      help="linux: filesystem root ('/' for this machine, or a snapshot folder); "
                           "windows: path to a secedit .inf export")
    scan.add_argument("--host", help="name shown in the report (default: source name)")
    scan.add_argument("--controls", default=str(DEFAULT_CONTROLS))
    scan.add_argument("--json-out", help="also save results as JSON evidence")
    args = p.parse_args(argv)

    controls = load_controls(args.controls)
    facts = COLLECTORS[args.platform](args.source)
    results = run_checks(controls, facts, args.platform)
    host = args.host or Path(args.source).name or args.source

    print_report(host, args.platform, results)
    if args.json_out:
        write_json(args.json_out, host, args.platform, args.source, results)
        print(f"\nJSON evidence written to {args.json_out}")

    # WHY: exit codes let a CI job or scheduler react: 0 compliant, 1 failures, 2 gaps only.
    statuses = {r.status for r in results}
    if Status.FAIL in statuses:
        return 1
    if statuses & {Status.ERROR, Status.NOT_COLLECTED}:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
