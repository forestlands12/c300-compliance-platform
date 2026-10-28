"""Load and validate the control catalogue (controls/*.yaml)."""
from __future__ import annotations

from pathlib import Path

import yaml

from .checks import OPERATORS
from .models import Control

REQUIRED_KEYS = ("id", "title", "platforms", "fact", "operator", "expected")
SEVERITIES = ("low", "medium", "high", "critical")
# WHAT: Security domains used to group controls on the dashboard. Add new ones here.
DOMAINS = {
    "identity": "Identity & Access",
    "remote": "Remote Access",
    "network": "Network & Firewall",
    "endpoint": "Endpoint Protection",
    "patching": "Patch Management",
    "logging": "Logging & Audit",
    "data": "Data Protection",
    "web": "Web Storefront",
    "general": "General",
}


class ControlFileError(ValueError):
    pass


# WHAT: Read the YAML catalogue, reject bad entries early, return Control objects.
# WHY: A typo in YAML should stop the run with a clear message, not give wrong results.
def load_controls(path: str | Path) -> list[Control]:
    # SECURITY: safe_load, never yaml.load, so a YAML file cannot run Python code.
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("controls"), list):
        raise ControlFileError(f"{path}: expected a top-level 'controls:' list")

    controls: list[Control] = []
    seen: set[str] = set()
    for i, raw in enumerate(data["controls"], start=1):
        missing = [k for k in REQUIRED_KEYS if k not in raw]
        if missing:
            raise ControlFileError(f"{path}: control #{i} is missing {missing}")
        if raw["id"] in seen:
            raise ControlFileError(f"{path}: duplicate control id {raw['id']}")
        if raw["operator"] not in OPERATORS:
            raise ControlFileError(
                f"{path}: {raw['id']} uses unknown operator '{raw['operator']}'"
            )
        severity = raw.get("severity", "medium")
        if severity not in SEVERITIES:
            raise ControlFileError(f"{path}: {raw['id']} has bad severity '{severity}'")
        domain = raw.get("domain", "general")
        if domain not in DOMAINS:
            raise ControlFileError(f"{path}: {raw['id']} has unknown domain '{domain}'")
        frameworks = raw.get("frameworks", {}) or {}
        if not isinstance(frameworks, dict):
            raise ControlFileError(f"{path}: {raw['id']} frameworks must be a mapping")
        seen.add(raw["id"])
        controls.append(
            Control(
                id=raw["id"],
                title=raw["title"],
                platforms=tuple(raw["platforms"]),
                fact=raw["fact"],
                operator=raw["operator"],
                expected=raw["expected"],
                severity=severity,
                rationale=raw.get("rationale", ""),
                remediation=raw.get("remediation", {}) or {},
                reference=raw.get("reference", ""),
                domain=domain,
                # WHY: YAML may read a requirement like 8.3 as a float; keep them as text.
                frameworks={str(k): str(v) for k, v in frameworks.items()},
            )
        )
    return controls
