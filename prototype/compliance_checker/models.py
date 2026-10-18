"""Core data types shared by every part of the checker."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# WHAT: The four possible outcomes of one control check.
class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    # The setting could not be read from the target, so we cannot say it passes.
    # Never treat this as a pass: an auditor would count it as a gap.
    NOT_COLLECTED = "NOT_COLLECTED"
    # The check itself broke (bad control definition, unexpected value type).
    ERROR = "ERROR"


# WHAT: One rule from controls/baseline.yaml (what to check and what is expected).
# WHY: frozen=True so a control cannot be changed by accident during a scan.
@dataclass(frozen=True)
class Control:
    id: str
    title: str
    platforms: tuple[str, ...]
    fact: str
    operator: str
    expected: Any
    severity: str = "medium"
    rationale: str = ""
    remediation: dict[str, str] = field(default_factory=dict)
    reference: str = ""

    def applies_to(self, platform: str) -> bool:
        return platform in self.platforms


# WHAT: The outcome of checking one Control against one host.
@dataclass
class Result:
    control: Control
    status: Status
    actual: Any = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control.id,
            "title": self.control.title,
            "severity": self.control.severity,
            "fact": self.control.fact,
            "operator": self.control.operator,
            "expected": self.control.expected,
            "actual": self.actual,
            "status": self.status.value,
            "message": self.message,
            "reference": self.control.reference,
        }
