"""Turn check results into a console report and a JSON evidence file."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Result, Status


# WHAT: Count results by status and work out the compliance score.
def summarise(results: list[Result]) -> dict[str, Any]:
    counts = {s.value: 0 for s in Status}
    for r in results:
        counts[r.status.value] += 1
    assessed = counts["PASS"] + counts["FAIL"]
    # WHY: score uses only assessed controls (PASS + FAIL); NOT_COLLECTED is shown separately, not hidden in the score.
    score = round(100 * counts["PASS"] / assessed, 1) if assessed else 0.0
    return {"total": len(results), **counts, "score_percent": score}


# WHAT: Print the human-readable table, failures first, then how to fix each failure.
# TODO(Ahmad, T-14): HTML report with the same content.
def print_report(host: str, platform: str, results: list[Result]) -> None:
    print(f"\nCompliance report for {host} ({platform})")
    print("=" * 96)
    print(f"{'STATUS':<14}{'ID':<11}{'SEV':<9}{'CONTROL':<44}{'ACTUAL'}")
    print("-" * 96)
    order = {Status.FAIL: 0, Status.ERROR: 1, Status.NOT_COLLECTED: 2, Status.PASS: 3}
    for r in sorted(results, key=lambda r: (order[r.status], r.control.id)):
        title = r.control.title if len(r.control.title) <= 42 else r.control.title[:39] + "..."
        print(f"{r.status.value:<14}{r.control.id:<11}{r.control.severity:<9}{title:<44}{r.actual!r}")
    s = summarise(results)
    print("-" * 96)
    print(f"Checked {s['total']} controls: {s['PASS']} pass, {s['FAIL']} fail, "
          f"{s['NOT_COLLECTED']} not collected, {s['ERROR']} error. "
          f"Score (pass / assessed): {s['score_percent']}%")

    failed = [r for r in results if r.status is Status.FAIL]
    if failed:
        print("\nHow to fix:")
        for r in failed:
            fix = r.control.remediation.get(platform, "see control definition")
            print(f"  [{r.control.id}] {fix}")


# WHAT: Save the results as JSON evidence (for history, drift and the report appendix).
# SECURITY: real scan output can reveal weaknesses; keep it out of Git (see .gitignore).
def write_json(path: str | Path, host: str, platform: str, source: str,
               results: list[Result]) -> None:
    doc = {
        "host": host,
        "platform": platform,
        "source": source,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarise(results),
        "results": [r.to_dict() for r in results],
    }
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
