"""Script-based scanning: run a shell scanner on the machine and read its verdicts.

WHY: for Ubuntu the team already has `scripts/fyp-scan.sh` (Ace), which checks the
42 CIS rules we kept using the audit method printed in the CIS PDF. Re-writing
those checks in Python would give us two versions of the same rule that can
disagree, so instead the platform runs the script and turns each of its lines
into a normal Result. Everything downstream (history, score, drift, dashboard,
report) is unchanged.

The script decides PASS or FAIL. This module decides nothing about security: it
copies the script to the machine, runs it read-only, parses the output, and
attaches the risk rating and business reason from controls/cis-ubuntu-24.04.yaml.

Output format of the script (one rule per line, see scripts/README.md):

    host|CIS-5.1.20|SSH root login disabled|no|yes|FAIL|2026-11-04T14:32:00+08:00
    host|SCORE|Compliance score|42 rules|15 passed|35%|<timestamp>

SECURITY: the script is uploaded to a private temp folder, run, then deleted.
It is never run from a world-writable path (a local user could swap it).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .loader import DOMAINS, ControlFileError
from .models import Control, Result, Status
from .targets import TargetError

SEVERITIES = ("low", "medium", "high", "critical")
# WHAT: how the script's own words map to our four statuses.
STATUSES = {"PASS": Status.PASS, "FAIL": Status.FAIL,
            # a check the script could not make is a gap, never a pass (D-04)
            "SKIP": Status.NOT_COLLECTED, "UNKNOWN": Status.NOT_COLLECTED,
            "ERROR": Status.ERROR}


@dataclass(frozen=True)
class Benchmark:
    name: str
    version: str
    profile: str
    script: str
    remediation: str
    platforms: tuple[str, ...]
    controls: dict[str, Control]   # keyed by rule id, e.g. "CIS-5.1.20"
    path: Path

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}"


# WHAT: Load a benchmark catalogue (controls/cis-ubuntu-24.04.yaml).
# WHY: the catalogue holds what the script cannot: risk rating, the business
# reason, the ISO mapping and which harden.sh step fixes the rule.
def load_benchmark(path: str | Path) -> Benchmark:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    meta = data.get("benchmark") or {}
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ControlFileError(f"{path}: expected a non-empty 'rules:' list")
    name = str(meta.get("name", path.stem))
    version = str(meta.get("version", ""))
    platforms = tuple(meta.get("platforms") or ["linux"])
    controls: dict[str, Control] = {}
    for raw in rules:
        for key in ("id", "title", "severity"):
            if key not in raw:
                raise ControlFileError(f"{path}: a rule is missing '{key}'")
        rid = str(raw["id"])
        if rid in controls:
            raise ControlFileError(f"{path}: duplicate rule id {rid}")
        if raw["severity"] not in SEVERITIES:
            raise ControlFileError(f"{path}: {rid} has unknown severity '{raw['severity']}'")
        domain = raw.get("domain", "general")
        if domain not in DOMAINS:
            raise ControlFileError(f"{path}: {rid} has unknown domain '{domain}'")
        controls[rid] = _control(raw, name, version, platforms, meta)
    return Benchmark(name=name, version=version, profile=str(meta.get("profile", "")),
                     script=str(meta.get("scanner", "")),
                     remediation=str(meta.get("remediation", "")),
                     platforms=platforms, controls=controls, path=path)


def _control(raw: dict[str, Any], name: str, version: str,
             platforms: tuple[str, ...], meta: dict[str, Any]) -> Control:
    cis_id = str(raw.get("cis_id", raw["id"]))
    risk = raw.get("risk") or {}
    # WHY: the rating is shown next to the finding, so a reader sees WHY it matters
    # ("likelihood 3 x impact 3 = 9, Critical"), not just a colour.
    rationale = str(raw.get("rationale", ""))
    if risk.get("score"):
        rationale = (f"Risk {risk.get('rating', '')} "
                     f"(likelihood {risk.get('likelihood')} x impact {risk.get('impact')} "
                     f"= {risk.get('score')}). {rationale}").strip()
    step = raw.get("harden_step")
    script = meta.get("remediation") or "scripts/harden.sh"
    fix = (f"{Path(script).name} fixes this, in its \"{step}\" step. "
           f"Dry-run it on the machine first: sudo ./{Path(script).name} --dry-run"
           if step else
           f"Not changed by {Path(script).name}: fix it by hand using the audit and remediation "
           f"text for {cis_id} in the {name} {version} PDF.")
    frameworks = {"cis_ubuntu_24_04": cis_id} if "ubuntu" in name.lower() else {}
    frameworks.update(raw.get("frameworks") or {})
    if raw.get("iso27001"):
        frameworks["iso27001"] = str(raw["iso27001"])
    return Control(
        id=str(raw["id"]),
        title=str(raw["title"]),
        platforms=platforms,
        # WHY: there is no collected "fact"; the script itself is the source.
        fact=f"{Path(script).parent.name}/{Path(meta.get('scanner', 'scan.sh')).name}:{cis_id}",
        operator="script",
        expected=raw.get("expected", ""),
        severity=str(raw["severity"]),
        rationale=rationale,
        remediation={"linux": fix},
        reference=f"{name} {version} section {cis_id}",
        domain=str(raw.get("domain", "general")),
        frameworks=frameworks,
    )


# WHAT: One parsed line of script output.
@dataclass(frozen=True)
class ScriptRow:
    rule_id: str
    title: str
    expected: str
    actual: str
    status: str


SCORE_ID = "SCORE"


# WHAT: Read the script's output. Ignores anything that is not a 7-field line,
# so a stray warning from sudo or the shell cannot break the scan.
def parse_output(text: str) -> tuple[list[ScriptRow], str | None]:
    rows: list[ScriptRow] = []
    score: str | None = None
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 6:
            continue
        _host, rule_id, title, expected, actual, status = parts[:6]
        if rule_id == SCORE_ID:
            score = f"{expected}, {actual} ({status})"
            continue
        if not rule_id or status.upper() not in STATUSES:
            continue
        rows.append(ScriptRow(rule_id, title, expected, actual, status.upper()))
    return rows, score


# WHAT: Turn parsed rows into Results, using the catalogue for risk and fixes.
# A rule the script reports but the catalogue does not know is still reported,
# so a rule Ace adds is never silently dropped.
def results_from_rows(rows: list[ScriptRow], benchmark: Benchmark) -> list[Result]:
    results = []
    for row in rows:
        control = benchmark.controls.get(row.rule_id)
        if control is None:
            control = Control(
                id=row.rule_id, title=row.title or row.rule_id,
                platforms=benchmark.platforms, fact=benchmark.script,
                operator="script", expected=row.expected, severity="medium",
                rationale=f"Reported by {Path(benchmark.script).name} but not yet in "
                          f"{benchmark.path.name}, so it has no agreed risk rating.",
                remediation={"linux": f"See {row.rule_id} in the {benchmark.label} PDF."},
                reference=f"{benchmark.label} (rule not in catalogue)", domain="general")
        status = STATUSES[row.status]
        message = "" if status is Status.PASS else f"expected {row.expected}, found {row.actual}"
        results.append(Result(control, status, row.actual, message))
    return results


# WHAT: Rules in the catalogue the script did not report at all.
# WHY: if the script dies half way (a missing command, no root), the rules it
# never reached must show as gaps, not quietly disappear and flatter the score.
def missing_results(rows: list[ScriptRow], benchmark: Benchmark, why: str) -> list[Result]:
    seen = {r.rule_id for r in rows}
    return [Result(c, Status.NOT_COLLECTED, None, why)
            for rid, c in benchmark.controls.items() if rid not in seen]


REMOTE_DIR = "/tmp/.c300-scan"


# WHAT: Copy the script to the machine, run it as root, read the verdicts, clean up.
# SECURITY: read-only. fyp-scan.sh only reads configuration; harden.sh (which does
# change the machine) is never run from here, by design (REQ-07).
def run_script_scan(target, benchmark: Benchmark, script_path: str | Path,
                    *, remote_script: str = "", timeout: int = 300) -> tuple[list[Result], str | None]:
    """Run the scanner on the machine and return (results, error).

    remote_script: a copy already installed on the machine (root-owned, e.g.
    /usr/local/sbin/fyp-scan.sh). Preferred: the script is then not writable by
    the scanning account, so a sudoers rule for it cannot be abused to get root.
    Without it the local copy is uploaded, which needs general sudo rights.
    """
    script_path = Path(script_path)
    if not script_path.is_file():
        return [], f"scanner script not found: {script_path}"
    if not hasattr(target, "run_script"):
        return [], (f"{getattr(target, 'description', 'this target')} cannot run a script "
                    "(script scans need transport: ssh or local)")
    uploaded = not remote_script
    remote = remote_script or f"{REMOTE_DIR}/{script_path.name}"
    try:
        if uploaded:
            target.put_text(remote, script_path.read_text(encoding="utf-8"),
                            mode=0o700, private_dir=REMOTE_DIR)
        rc, out, err = target.run_script(remote, timeout=timeout)
    except TargetError as exc:
        return [], str(exc)
    finally:
        if uploaded:
            try:
                target.run(f"rm -rf -- {REMOTE_DIR}")
            except Exception:  # cleanup is best effort; never fail a scan over it
                pass

    rows, _score = parse_output(out)
    if not rows:
        return [], _no_output_reason(rc, out, err, script_path.name)
    results = results_from_rows(rows, benchmark)
    if rc != 0 and len(rows) < len(benchmark.controls):
        why = (f"{script_path.name} stopped early (exit code {rc}): "
               f"{_tail(err) or _tail(out) or 'no error message'}")
        results += missing_results(rows, benchmark, why)
    else:
        results += missing_results(rows, benchmark,
                                   f"{script_path.name} did not report this rule")
    return results, None


def _tail(text: str, limit: int = 200) -> str:
    text = " ".join((text or "").split())
    return text[-limit:]


# WHY: "no output" almost always means sudo asked for a password. Say so plainly
# instead of leaving a blank scan the reader has to guess about.
def _no_output_reason(rc: int, out: str, err: str, name: str) -> str:
    joined = f"{out}\n{err}".lower()
    if "password is required" in joined or "sudo:" in joined or "a terminal is required" in joined:
        return (f"{name} could not run as root: this account needs a password for sudo. "
                "Give the scanning account passwordless sudo for the scan, or run the "
                "script on the machine and import its output.")
    if "permission denied" in joined:
        return f"{name} could not run: permission denied. Is the account allowed to use sudo?"
    if "not found" in joined and "command" in joined:
        return f"{name} needs a command this machine does not have: {_tail(err) or _tail(out)}"
    return (f"{name} produced no readable results (exit code {rc}): "
            f"{_tail(err) or _tail(out) or 'no output at all'}")


# WHAT: Compare the script and the catalogue. Used by `script-check` so the team
# notices when one is edited without the other.
def compare(benchmark: Benchmark, script_path: str | Path) -> dict[str, list[str]]:
    text = Path(script_path).read_text(encoding="utf-8")
    in_script = {f"CIS-{m}" for m in re.findall(r'report\s+"CIS-([0-9.]+)"', text)}
    in_catalogue = set(benchmark.controls)
    return {"only_in_script": sorted(in_script - in_catalogue),
            "only_in_catalogue": sorted(in_catalogue - in_script),
            "both": sorted(in_script & in_catalogue)}
