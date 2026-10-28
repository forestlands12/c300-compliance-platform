"""Scan engine: collect -> check -> store, for every host in the inventory.

This is what the dashboard's "Run scan" button, the scheduled task and the
`scan-all` command all call, so the three always behave the same.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from .checks import run_checks
from .collectors import collect_host
from .inventory import Host, Inventory
from .models import Control
from .targets import TargetError


# WHAT: Scan one host. Never raises: an unreachable host becomes an error row.
def scan_host(host: Host, controls: list[Control]) -> tuple[list[dict[str, Any]], str | None]:
    try:
        target = host.open()
    except TargetError as exc:
        return [], str(exc)
    try:
        facts = collect_host(host.platform, target, host.services)
    except TargetError as exc:
        return [], str(exc)
    except Exception as exc:  # a collector bug must not stop the other hosts
        return [], f"collector crashed: {type(exc).__name__}: {exc}"
    finally:
        target.close()
    return [r.to_dict() for r in run_checks(controls, facts, host.tags)], None


# WHAT: Scan every host (in parallel) and save one run to the history store.
# WHY: parallel, because an unreachable VM waits for a network timeout and should
# not hold up the others.
def run_scan(inventory: Inventory, controls: list[Control], store, trigger: str = "cli",
             on_progress: Callable[[str, str], None] | None = None) -> int:
    run_id = store.start_run(trigger, str(inventory.path), inventory.organisation)
    progress = on_progress or (lambda host, state: None)

    def job(host: Host):
        progress(host.name, "scanning")
        t0 = time.monotonic()
        results, error = scan_host(host, controls)
        progress(host.name, "error" if error else "done")
        return host, results, error, time.monotonic() - t0

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(job, inventory.hosts))
    for host, results, error, _ in outcomes:
        hs_id = store.add_host_scan(run_id, host, results, error)
        # WHY: the first good scan of a host is its baseline ("fresh install = perfect
        # state", supervisor 21 Oct). The team can move it later with `baseline`.
        if error is None and store.baseline(host.name) is None:
            store.set_baseline(host.name, hs_id)
    store.finish_run(run_id)
    return run_id
