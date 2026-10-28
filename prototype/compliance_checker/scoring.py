"""Scores, drift and the dashboard summary, all computed from stored results.

Every number on the dashboard comes from here, so the report and the
dashboard can never disagree. Results are the dicts made by Result.to_dict().
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .loader import DOMAINS

# WHY: a weighted score, so one failed high-severity control costs more than a
# failed low one. Plain pass-rate is still shown next to it for transparency.
WEIGHTS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# WHAT: Frameworks shown on the dashboard. Mapping is indicative, see controls/baseline.yaml.
FRAMEWORKS = {
    "baseline": "C300 SME baseline (CIS-style)",
    "cis_v8": "CIS Controls v8",
    "pci_dss_v4": "PCI DSS v4.0 (card payments)",
}


def counts(results: list[dict]) -> dict[str, int]:
    c = {"PASS": 0, "FAIL": 0, "NOT_COLLECTED": 0, "ERROR": 0}
    for r in results:
        c[r["status"]] = c.get(r["status"], 0) + 1
    c["total"] = len(results)
    return c


# WHAT: Weighted posture score in percent over assessed controls (PASS + FAIL).
# WHY: NOT_COLLECTED is left out of the score and shown as a coverage gap instead,
# so a host we could not read never looks compliant (D-04).
def posture(results: list[dict]) -> float | None:
    got = total = 0
    for r in results:
        if r["status"] in ("PASS", "FAIL"):
            w = WEIGHTS.get(r["severity"], 2)
            total += w
            got += w if r["status"] == "PASS" else 0
    return round(100 * got / total, 1) if total else None


def pass_rate(results: list[dict]) -> float | None:
    c = counts(results)
    assessed = c["PASS"] + c["FAIL"]
    return round(100 * c["PASS"] / assessed, 1) if assessed else None


def domain_scores(results: list[dict]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        groups[r.get("domain", "general")].append(r)
    rows = [{"domain": d, "label": DOMAINS.get(d, d), "score": posture(rs), **counts(rs)}
            for d, rs in groups.items()]
    # Lowest score first: the dashboard ranks the weakest domains at the top.
    return sorted(rows, key=lambda x: (x["score"] is None, x["score"] if x["score"] is not None else 0))


# WHAT: Requirement-level compliance per framework.
# A requirement passes only when every assessed check mapped to it passes, on every host.
def framework_scores(results: list[dict]) -> list[dict[str, Any]]:
    out = []
    for key, name in FRAMEWORKS.items():
        reqs: dict[str, list[dict]] = defaultdict(list)
        for r in results:
            req = r["control_id"] if key == "baseline" else (r.get("frameworks") or {}).get(key)
            if req:
                reqs[req].append(r)
        passed = failed = unknown = 0
        for rs in reqs.values():
            statuses = {r["status"] for r in rs}
            if "FAIL" in statuses or "ERROR" in statuses:
                failed += 1
            elif "PASS" in statuses:
                passed += 1
            else:
                unknown += 1
        mapped = [r for rs in reqs.values() for r in rs]
        out.append({"key": key, "name": name, "requirements": len(reqs),
                    "requirements_passed": passed, "requirements_failed": failed,
                    "requirements_unknown": unknown, "checks_pass_rate": pass_rate(mapped),
                    **counts(mapped)})
    return out


def remediation_for(result: dict, platform: str) -> str:
    rem = result.get("remediation") or {}
    return rem.get(platform) or next(iter(rem.values()), "See control definition.")


# WHAT: What changed between two scans of the same host (drift).
def drift(old: list[dict], new: list[dict]) -> list[dict[str, Any]]:
    before = {r["control_id"]: r for r in old}
    changes = []
    for r in new:
        o = before.get(r["control_id"])
        if o is None or (o["status"] == r["status"] and o.get("actual") == r.get("actual")):
            continue
        if o["status"] != "FAIL" and r["status"] == "FAIL":
            direction = "worse"
        elif o["status"] == "FAIL" and r["status"] == "PASS":
            direction = "better"
        else:
            direction = "changed"
        changes.append({"control_id": r["control_id"], "title": r["title"],
                        "severity": r["severity"], "from": o["status"], "to": r["status"],
                        "old_actual": o.get("actual"), "new_actual": r.get("actual"),
                        "direction": direction})
    rank = {"worse": 0, "changed": 1, "better": 2}
    return sorted(changes, key=lambda c: (rank[c["direction"]], SEV_ORDER.get(c["severity"], 9)))


# WHAT: Everything the dashboard shows, for the latest finished run.
def build_summary(store, organisation: str = "", environment: str = "") -> dict[str, Any]:
    runs = store.runs(limit=30)
    summary: dict[str, Any] = {"organisation": organisation, "environment": environment,
                               "has_data": bool(runs)}
    if not runs:
        return summary

    trend = []
    for run in runs:
        rs = [r for hs in store.host_scans(run["id"]) if not hs["error"]
              for r in store.results(hs["id"])]
        trend.append({"run_id": run["id"], "at": run["started_at"], "trigger": run["trigger"],
                      "score": posture(rs)})
    latest = runs[-1]
    summary["run"] = latest
    summary["organisation"] = organisation or latest.get("organisation", "")
    summary["trend"] = trend

    hosts, all_results, failures, gaps, drift_rows = [], [], [], [], []
    for hs in store.host_scans(latest["id"]):
        results = store.results(hs["id"])
        all_results.extend(results)
        base = store.baseline(hs["host"])
        ref = base if base and base["id"] != hs["id"] else store.previous_host_scan(hs["host"], hs["id"])
        changes = drift(store.results(ref["id"]), results) if ref and not hs["error"] else []
        for c in changes:
            drift_rows.append({**c, "host": hs["host"]})
        hosts.append({
            "name": hs["host"], "role": hs["role"], "kind": hs["kind"], "platform": hs["platform"],
            "transport": hs["transport"], "location": hs["location"], "error": hs["error"],
            "scanned_at": hs["scanned_at"], "host_scan_id": hs["id"],
            "score": posture(results), "pass_rate": pass_rate(results), **counts(results),
            "baseline_scan_id": base["id"] if base else None,
            "baseline_set_at": base["baseline_set_at"] if base else None,
            "drift_against": ("baseline" if base and base["id"] != hs["id"]
                              else "is baseline" if base else "previous scan" if ref else None),
            "drift_worse": sum(c["direction"] == "worse" for c in changes),
        })
        for r in results:
            row = {**r, "host": hs["host"], "fix": remediation_for(r, hs["platform"])}
            if r["status"] == "FAIL":
                failures.append(row)
            elif r["status"] in ("NOT_COLLECTED", "ERROR"):
                gaps.append(row)

    failures.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["host"], r["control_id"]))
    hosts.sort(key=lambda h: (h["error"] is None, h["score"] if h["score"] is not None else 101))
    score = posture(all_results)
    prev = next((t["score"] for t in reversed(trend[:-1]) if t["score"] is not None), None)

    # Recommendation: what the score would be if every high/critical failure were fixed.
    fixed = [{**r, "status": "PASS"} if r["status"] == "FAIL" and r["severity"] in ("high", "critical")
             else r for r in all_results]
    n_high = sum(1 for r in failures if r["severity"] in ("high", "critical"))

    summary.update({
        "score": score,
        "pass_rate": pass_rate(all_results),
        "delta": None if score is None or prev is None else round(score - prev, 1),
        "counts": counts(all_results),
        "hosts": hosts,
        "top_failures": failures,
        "domains": domain_scores(all_results),
        "frameworks": framework_scores(all_results),
        "drift": drift_rows,
        "gaps": gaps,
        "recommendation": {"high_failures": n_high, "score_if_fixed": posture(fixed)},
    })
    return summary
