"""Standalone HTML scan report: one file an assessor can open, print, or save as PDF.

Made from the same numbers as the dashboard (scoring.build_summary), so the report
and the dashboard cannot disagree. No JavaScript and no web fonts: it works offline.
"""
from __future__ import annotations

import json
from datetime import datetime
from html import escape
from typing import Any

from .scoring import build_summary

STYLE = """
:root { color-scheme: light; }
body { font-family: "Segoe UI", system-ui, Arial, sans-serif; color: #1c1f26; background: #fff;
  max-width: 980px; margin: 0 auto; padding: 32px 24px 48px; line-height: 1.45; font-size: 14px; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 32px 0 10px; border-bottom: 2px solid #dfe3ea; padding-bottom: 6px; }
h3 { font-size: 15px; margin: 22px 0 8px; }
.sub { color: #5b6270; margin: 0 0 18px; }
.score { display: flex; gap: 24px; align-items: center; flex-wrap: wrap; margin: 14px 0; }
.big { font-size: 54px; font-weight: 700; line-height: 1; }
.good { color: #1a7f37; } .warn { color: #9a6700; } .bad { color: #cf222e; }
.kpis { display: flex; gap: 12px; flex-wrap: wrap; }
.kpi { border: 1px solid #dfe3ea; border-radius: 8px; padding: 8px 14px; min-width: 110px; }
.kpi b { display: block; font-size: 20px; } .kpi span { color: #5b6270; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 4px; }
th, td { border: 1px solid #dfe3ea; padding: 6px 9px; text-align: left; vertical-align: top; }
th { background: #f3f5f9; font-size: 12px; }
td.num { text-align: right; white-space: nowrap; }
.sev { font-weight: 700; font-size: 11px; text-transform: uppercase; }
.sev.critical, .sev.high { color: #cf222e; } .sev.medium { color: #9a6700; } .sev.low { color: #0969da; }
.st-PASS { color: #1a7f37; font-weight: 700; } .st-FAIL { color: #cf222e; font-weight: 700; }
.st-NOT_COLLECTED, .st-ERROR { color: #9a6700; font-weight: 700; }
.caution { background: #fff7ed; border-left: 4px solid #b54708; padding: 8px 12px; margin: 10px 0; color: #4a2c0b; }
.note { background: #f6f8fa; border-left: 4px solid #0969da; padding: 8px 12px; margin: 10px 0; color: #3b4150; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.muted { color: #5b6270; }
.empty { color: #5b6270; font-style: italic; margin: 6px 0; }
@media print { body { padding: 0; } h2 { break-after: avoid; } tr { break-inside: avoid; } .host { break-before: page; } }
"""


def _e(v: Any) -> str:
    return escape(str(v), quote=True)


def _show(v: Any) -> str:
    # SECURITY: values come from scanned machines, so every one is escaped before it is written.
    if v is None or v == "":
        return "not found"
    return _e(json.dumps(v) if isinstance(v, (dict, list)) else v)


def _expected(r: dict) -> str:
    # WHY: a built-in control reads as "gte 14"; a rule checked by the shell
    # scanner has no operator to show, just what the CIS audit expects.
    op = r.get("operator", "")
    return _show(r["expected"]) if op == "script" else f"{_e(op)} {_show(r['expected'])}"


def _pct(v: float | None) -> str:
    return "–" if v is None else f"{round(v)}%"


def _tone(v: float | None) -> str:
    return "" if v is None else "good" if v >= 80 else "warn" if v >= 60 else "bad"


def _table(head: list[str], rows: list[list[str]], num_cols: tuple[int, ...] = ()) -> str:
    if not rows:
        return ""
    th = "".join(f"<th>{_e(h)}</th>" for h in head)
    body = "".join("<tr>" + "".join(
        f'<td class="num">{c}</td>' if i in num_cols else f"<td>{c}</td>" for i, c in enumerate(r)) + "</tr>"
        for r in rows)
    return f"<table><tr>{th}</tr>{body}</table>"


def _sev(s: str) -> str:
    return f'<span class="sev {_e(s)}">{_e(s)}</span>'


# WHAT: Build the full report for the latest saved run, as one HTML string.
# `store` supplies each machine's full results for the appendix; `summary` can be passed
# in when the caller has already built it.
def render_report(store, organisation: str = "", environment: str = "",
                  summary: dict[str, Any] | None = None) -> str:
    s = summary or build_summary(store, organisation, environment)
    if not s.get("has_data"):
        return _page(s.get("organisation") or organisation or "Compliance report",
                     '<p class="empty">No scans have been saved yet. Run a scan first.</p>')
    org = s.get("organisation") or organisation or "Compliance report"
    run = s["run"]
    c = s["counts"]
    not_checked = c["NOT_COLLECTED"] + c["ERROR"]
    when = run["started_at"]
    try:
        when = datetime.fromisoformat(run["started_at"]).strftime("%d %B %Y, %H:%M UTC")
    except ValueError:
        pass
    delta = s.get("delta")
    delta_txt = "" if delta is None else (
        f'<div class="{"good" if delta > 0 else "bad" if delta < 0 else "muted"}">'
        f'{"+" if delta > 0 else ""}{delta} points since the previous scan</div>')
    rec = s["recommendation"]

    parts = [f"<h1>{_e(org)}: configuration compliance report</h1>",
             f'<p class="sub">Scan #{_e(run["id"])} · {_e(when)} · trigger: {_e(run["trigger"])} · '
             f'{len(s["hosts"])} machines · {_e(environment or s.get("environment", ""))}</p>']

    parts.append("<h2>1. Summary</h2>")
    parts.append(f'<div class="score"><div><div class="big {_tone(s["score"])}">{_pct(s["score"])}</div>'
                 f'<div class="muted">weighted posture score</div>{delta_txt}</div>'
                 '<div class="kpis">'
                 f'<div class="kpi"><b>{c["PASS"]}</b><span>Passed</span></div>'
                 f'<div class="kpi"><b>{c["FAIL"]}</b><span>Failed</span></div>'
                 f'<div class="kpi"><b>{not_checked}</b><span>Not checked</span></div>'
                 f'<div class="kpi"><b>{_pct(s["pass_rate"])}</b><span>Plain pass rate</span></div>'
                 "</div></div>")
    cov = s.get("coverage") or {}
    if cov.get("low"):
        # FIX(B-08, 4 Nov 2026, Claude): a scan that could read almost nothing used to
        # show a confident score (100% from one check on a real VM). Say it plainly.
        parts.append(f'<p class="caution"><b>Read this score with care:</b> only '
                     f'{cov["assessed"]} of {cov["total"]} checks could actually be made '
                     f'({_pct(cov["percent"])} coverage). The score below is calculated from '
                     f'those {cov["assessed"]} alone, so it is not yet a fair picture of the '
                     f'machines. Section 5 lists what could not be checked and why.</p>')
    if rec["high_failures"]:
        parts.append(f'<p class="note"><b>Recommendation:</b> fixing the {rec["high_failures"]} '
                     f'high-severity failures first would raise the score from {_pct(s["score"])} '
                     f'to {_pct(rec["score_if_fixed"])}.</p>')
    parts.append('<p class="note"><b>How the score works:</b> each failed check costs its severity weight '
                 "(low 1, medium 2, high 3, critical 4). Checks that could not be read are left out of the "
                 "score and listed in section 5; they are never counted as a pass.</p>")

    parts.append("<h2>2. Machines</h2>")
    parts.append(_table(
        ["Machine", "Role", "Platform", "Score", "Failed", "Compared with"],
        [[_e(h["name"]), _e(h["role"]), _e(h["platform"]),
          "unreachable" if h["error"] else f'<b class="{_tone(h["score"])}">{_pct(h["score"])}</b>',
          "–" if h["error"] else _e(h["FAIL"]), _e(h["drift_against"] or "first scan")]
         for h in s["hosts"]], num_cols=(3, 4)))
    for h in s["hosts"]:
        if h["error"]:
            parts.append(f'<p class="empty">{_e(h["name"])} could not be scanned: {_e(h["error"])}</p>')

    parts.append("<h2>3. Failed checks, most severe first</h2>")
    fails = s["top_failures"]
    parts.append(_table(
        ["Machine", "Check", "Severity", "Found", "Expected", "How to fix"],
        [[_e(r["host"]), f'{_e(r["control_id"])}<br>{_e(r["title"])}', _sev(r["severity"]),
          f'<span class="mono">{_show(r["actual"])}</span>',
          f'<span class="mono">{_expected(r)}</span>', _e(r["fix"])]
         for r in fails]) or '<p class="empty">No failed checks.</p>')

    parts.append("<h2>4. Configuration drift</h2>")
    parts.append('<p class="muted">What changed since each machine\'s baseline (or since its previous scan '
                 "when no baseline exists yet).</p>")
    arrow = {"worse": "worse", "better": "fixed", "changed": "changed"}
    parts.append(_table(
        ["Machine", "Check", "Severity", "Was", "Now", "Direction"],
        [[_e(r["host"]), f'{_e(r["control_id"])}<br>{_e(r["title"])}', _sev(r["severity"]),
          f'<span class="mono">{_show(r["old_actual"])}</span>', f'<span class="mono">{_show(r["new_actual"])}</span>',
          f'<b class="{"bad" if r["direction"] == "worse" else "good" if r["direction"] == "better" else "warn"}">'
          f'{arrow[r["direction"]]}</b>'] for r in s["drift"]]) or '<p class="empty">No drift detected.</p>')

    parts.append("<h2>5. Checks that could not be made</h2>")
    parts.append(_table(
        ["Machine", "Check", "Why"],
        [[_e(r["host"]), f'{_e(r["control_id"])}<br>{_e(r["title"])}', _e(r["message"])] for r in s["gaps"]])
        or '<p class="empty">Every applicable check was collected.</p>')

    parts.append("<h2>6. Framework view</h2>")
    parts.append('<p class="note">Indicative mapping of our checks to each framework. It has not yet been '
                 "verified against the official documents (task T-05), so it is not a certification.</p>")
    parts.append(_table(
        ["Framework", "Requirements fully passed", "Checks passed", "Checks mapped"],
        [[_e(f["name"]), f'{f["requirements_passed"]} / {f["requirements"]}', _pct(f["checks_pass_rate"]),
          _e(f["total"])] for f in s["frameworks"]], num_cols=(1, 2, 3)))

    parts.append("<h2>Appendix: every result, per machine</h2>")
    order = {"FAIL": 0, "ERROR": 1, "NOT_COLLECTED": 2, "PASS": 3}
    for h in s["hosts"]:
        parts.append(f'<div class="host"><h3>{_e(h["name"])} <span class="muted">· {_e(h["role"])} · '
                     f'{_e(h["platform"])}</span></h3>')
        if h["error"]:
            parts.append(f'<p class="empty">Not scanned: {_e(h["error"])}</p></div>')
            continue
        rows = sorted(store.results(h["host_scan_id"]),
                      key=lambda r: (order.get(r["status"], 9), r["control_id"]))
        parts.append(_table(
            ["Status", "Check", "Severity", "Found", "Expected"],
            [[f'<span class="st-{_e(r["status"])}">{_e(r["status"].replace("_", " "))}</span>',
              f'{_e(r["control_id"])}<br>{_e(r["title"])}', _sev(r["severity"]),
              f'<span class="mono">{_show(r["actual"])}</span>',
              f'<span class="mono">{_expected(r)}</span>'] for r in rows]))
        parts.append("</div>")

    parts.append(f'<p class="muted" style="margin-top:32px">Generated by the C300 Compliance Automation and '
                 f'Validation Platform (read-only scanner), {_e(datetime.now().strftime("%d %B %Y"))}.</p>')
    return _page(f"{org}: compliance report", "\n".join(parts))


def _page(title: str, body: str) -> str:
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>{_e(title)}</title><style>{STYLE}</style></head><body>\n{body}\n</body></html>\n")
