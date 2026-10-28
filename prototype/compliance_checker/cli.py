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

PROTOTYPE = Path(__file__).resolve().parent.parent
DEFAULT_CONTROLS = PROTOTYPE / "controls" / "baseline.yaml"
DEFAULT_DB = PROTOTYPE / "data" / "history.db"
DEMO_DB = PROTOTYPE / "data" / "demo-history.db"


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

    # WHAT: Scan every host in an inventory and save the run (used by the weekly scheduled task).
    sa = sub.add_parser("scan-all", help="scan every host in an inventory and save to history")
    _common(sa)
    sa.add_argument("--trigger", default="cli", choices=["cli", "scheduled", "manual"],
                    help="label stored with the run (use 'scheduled' in Task Scheduler / cron)")

    db = sub.add_parser("dashboard", help="start the web dashboard with the one-click scan button")
    _common(db)
    db.add_argument("--port", type=int, default=8300)
    db.add_argument("--host", default="127.0.0.1",
                    help="address to listen on (default: this PC only)")

    bl = sub.add_parser("baseline", help="mark each host's latest scan as its baseline")
    _common(bl)
    bl.add_argument("--host", dest="target_host", help="only this host (default: all hosts)")

    dm = sub.add_parser("demo", help="demo playground: reset sample hosts, or apply deliberate drift")
    dm.add_argument("action", choices=["reset", "drift"])

    ex = sub.add_parser("export-windows-script",
                        help="write collect_windows.ps1 for offline Windows collection")
    ex.add_argument("--out", default="collect_windows.ps1")

    args = p.parse_args(argv)
    if args.command != "scan":
        return _run_command(args)

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


def _common(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--inventory", help="inventory YAML (default: the demo playground)")
    sp.add_argument("--controls", default=str(DEFAULT_CONTROLS))
    sp.add_argument("--db", help="history database (default: data/history.db, "
                                 "or data/demo-history.db for the demo)")


def _paths(args) -> tuple[Path, Path]:
    from . import demo
    if args.inventory:
        return Path(args.inventory), Path(args.db or DEFAULT_DB)
    demo.ensure()  # WHY: first run on a new laptop works with no setup at all
    return demo.DEMO_INVENTORY, Path(args.db or DEMO_DB)


# WHAT: The newer multi-host commands (scan-all, dashboard, baseline, demo, export).
def _run_command(args) -> int:
    from . import demo
    from .engine import run_scan
    from .inventory import load_inventory
    from .scoring import build_summary
    from .store import Store

    if args.command == "demo":
        if args.action == "reset":
            print(f"Demo hosts reset to their baseline state in {demo.reset()}")
        else:
            print("Deliberate drift applied to the demo hosts:")
            for line in demo.drift():
                print(f"  - {line}")
            print("Now run a scan (dashboard button or scan-all) to see it caught.")
        return 0
    if args.command == "export-windows-script":
        from .windows_ps import offline_script
        # WHY: utf-8-sig, because Windows PowerShell 5.1 misreads UTF-8 without a BOM.
        Path(args.out).write_text(offline_script(), encoding="utf-8-sig")
        print(f"Wrote {args.out}")
        return 0

    inv_path, db_path = _paths(args)
    inventory = load_inventory(inv_path)
    controls = load_controls(args.controls)
    store = Store(db_path)

    if args.command == "scan-all":
        run_id = run_scan(inventory, controls, store, trigger=args.trigger,
                          on_progress=lambda h, s: print(f"  {h:<20} {s}"))
        summary = build_summary(store, inventory.organisation)
        print(f"Run {run_id} saved to {db_path}. Posture score: {summary['score']}%")
        for h in summary["hosts"]:
            state = f"ERROR {h['error']}" if h["error"] else f"{h['score']}%  ({h['FAIL']} fail)"
            print(f"  {h['name']:<20} {state}")
        return 1 if summary["counts"]["FAIL"] else 0
    if args.command == "baseline":
        names = [args.target_host] if args.target_host else [h.name for h in inventory.hosts]
        for name in names:
            hs = store.set_baseline(name)
            print(f"  {name:<20} " + (f"baseline = scan #{hs}" if hs else "no successful scan yet"))
        return 0
    if args.command == "dashboard":
        from .web import create_app
        app = create_app(inventory, controls, store)
        print(f"Dashboard for {inventory.organisation}: http://{args.host}:{args.port}  (Ctrl+C to stop)")
        if args.host not in ("127.0.0.1", "localhost"):
            print("WARNING: the dashboard is reachable from other machines on this network.")
        app.run(host=args.host, port=args.port, debug=False, threaded=True)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
