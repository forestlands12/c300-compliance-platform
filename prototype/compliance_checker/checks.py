"""Rule engine: compare a collected fact against a control's expected value."""
from __future__ import annotations

from typing import Any, Callable

from .models import Control, Result, Status


def _between(actual: Any, expected: Any) -> bool:
    low, high = expected
    return low <= actual <= high


# WHAT: The comparison operators a control may use. Add new ones here and in the standard doc.
OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, e: a == e,
    "ne": lambda a, e: a != e,
    "gte": lambda a, e: a >= e,
    "lte": lambda a, e: a <= e,
    "between": _between,  # inclusive, expected = [low, high]
    "in": lambda a, e: a in e,
    "not_in": lambda a, e: a not in e,
}


# WHAT: Check one control against the facts collected from one host.
def evaluate(control: Control, facts: dict[str, Any]) -> Result:
    # WHY: Missing data must never count as PASS (decision D-04), or the report gives false assurance.
    if control.fact not in facts or facts[control.fact] is None:
        return Result(control, Status.NOT_COLLECTED,
                      message=f"fact '{control.fact}' was not found on the target")

    actual = facts[control.fact]
    try:
        ok = OPERATORS[control.operator](actual, control.expected)
    except Exception as exc:  # bad types in a control or fact: report, don't crash the run
        return Result(control, Status.ERROR, actual, f"{type(exc).__name__}: {exc}")

    if ok:
        return Result(control, Status.PASS, actual)
    return Result(control, Status.FAIL, actual,
                  f"expected {control.operator} {control.expected!r}, found {actual!r}")


# WHAT: Run every control that applies to this host.
# `platform` is "linux"/"windows", or a set of tags such as {"linux", "nginx"}.
def run_checks(controls: list[Control], facts: dict[str, Any],
               platform: str | set[str]) -> list[Result]:
    return [evaluate(c, facts) for c in controls if c.applies_to(platform)]
