"""Check registry.

A check is a pure function over an evidence snapshot (a dict) that returns a
CheckResult. Checks never call APIs, so every result can be reproduced from the
stored evidence file alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..models import CheckResult, Finding, Status

CheckFn = Callable[[dict], CheckResult]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    source: str
    controls: tuple[str, ...]
    remediation: str
    func: CheckFn


REGISTRY: dict[str, Check] = {}


def check(*, id: str, title: str, source: str, controls: list[str], remediation: str):
    def decorator(fn: CheckFn) -> CheckFn:
        if id in REGISTRY:
            raise ValueError(f"Duplicate check id {id}")
        REGISTRY[id] = Check(id, title, source, tuple(controls), remediation, fn)
        return fn

    return decorator


def run_check(c: Check, snapshot: dict) -> Finding:
    try:
        result = c.func(snapshot)
    except (KeyError, TypeError) as exc:
        result = CheckResult(Status.ERROR, f"Evidence is missing an expected field: {exc}")
    return Finding(
        check_id=c.id,
        title=c.title,
        source=c.source,
        status=result.status,
        detail=result.detail,
        controls=list(c.controls),
        remediation=c.remediation,
        failing_resources=result.failing_resources,
    )


def checks_for(source: str) -> list[Check]:
    return [c for c in REGISTRY.values() if c.source == source]


# Import check modules so they register themselves.
from . import aws_checks, github_checks  # noqa: E402,F401
