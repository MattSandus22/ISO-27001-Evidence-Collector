"""Run checks over evidence and roll findings up to Annex A controls."""

from __future__ import annotations

from importlib import resources

import yaml

from .checks import REGISTRY, checks_for, run_check
from .models import ControlResult, ControlStatus, Finding, Status


def load_controls() -> dict[str, dict]:
    text = resources.files("iso27k").joinpath("data/annex_a.yaml").read_text()
    return yaml.safe_load(text)["controls"]


def run_checks(snapshots: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for snap in snapshots:
        findings.extend(run_check(c, snap) for c in checks_for(snap["source"]))
    return findings


def _control_sort_key(cid: str) -> tuple[int, int]:
    major, minor = cid.split(".")
    return int(major), int(minor)


def summarize_controls(findings: list[Finding], controls: dict[str, dict] | None = None) -> list[ControlResult]:
    controls = controls or load_controls()
    results = []
    for cid in sorted(controls, key=_control_sort_key):
        related = [f for f in findings if cid in f.controls and f.status != Status.NOT_APPLICABLE]
        failing = [f.check_id for f in related if f.status == Status.FAIL]
        if not related:
            status = ControlStatus.NOT_ASSESSED
        elif failing:
            status = ControlStatus.GAP
        elif any(f.status == Status.ERROR for f in related):
            status = ControlStatus.INCOMPLETE
        else:
            status = ControlStatus.SUPPORTED
        results.append(ControlResult(
            control_id=cid,
            title=controls[cid]["title"],
            theme=controls[cid]["theme"],
            status=status,
            check_ids=[f.check_id for f in related],
            failing_check_ids=failing,
        ))
    return results


def unmapped_controls() -> list[str]:
    """Control IDs referenced by checks but missing from annex_a.yaml (should be empty)."""
    known = load_controls()
    return sorted({cid for c in REGISTRY.values() for cid in c.controls if cid not in known})
