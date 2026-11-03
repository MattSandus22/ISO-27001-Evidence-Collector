"""Render assessment results as Markdown, JSON or CSV."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter

from . import __version__
from .models import ControlResult, ControlStatus, Finding, Status, utcnow

ICON = {
    Status.PASS: "✅", Status.FAIL: "❌", Status.ERROR: "⚠️", Status.NOT_APPLICABLE: "➖",
    ControlStatus.SUPPORTED: "✅", ControlStatus.GAP: "❌",
    ControlStatus.INCOMPLETE: "⚠️", ControlStatus.NOT_ASSESSED: "➖",
}

DISCLAIMER = (
    "Automated checks show whether specific technical configurations are in place at the time of "
    "collection. They support, but do not by themselves demonstrate, conformity with ISO/IEC 27001. "
    "Each control also requires documented policy, ownership and operating evidence reviewed by a "
    "qualified auditor."
)


def to_json(controls: list[ControlResult], findings: list[Finding], manifest: list[dict]) -> str:
    return json.dumps({
        "generated_at": utcnow(),
        "tool_version": __version__,
        "evidence": manifest,
        "controls": [c.to_dict() for c in controls],
        "findings": [f.to_dict() for f in findings],
    }, indent=2) + "\n"


def to_csv(controls: list[ControlResult], findings: list[Finding], manifest: list[dict]) -> str:
    """Control-level rows, convenient for pasting into a Statement of Applicability workbook."""
    by_id = {f.check_id: f for f in findings}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["control_id", "title", "theme", "status", "checks", "failing_checks", "remediation"])
    for c in controls:
        remediation = " | ".join(by_id[cid].remediation for cid in c.failing_check_ids)
        w.writerow([c.control_id, c.title, c.theme, c.status.value,
                    ";".join(c.check_ids), ";".join(c.failing_check_ids), remediation])
    return buf.getvalue()


def to_markdown(controls: list[ControlResult], findings: list[Finding], manifest: list[dict]) -> str:
    lines: list[str] = []
    add = lines.append
    scopes = ", ".join(f"`{e['scope']}`" for e in manifest) or "n/a"

    add("# ISO/IEC 27001:2022 Technical Evidence Report")
    add("")
    add(f"Generated {utcnow()} by iso27k-evidence v{__version__}. Scope: {scopes}.")
    add("")

    cstats = Counter(c.status for c in controls)
    fstats = Counter(f.status for f in findings)
    add("## Summary")
    add("")
    add("| Controls | Count | | Checks | Count |")
    add("|---|---|---|---|---|")
    rows = list(zip(ControlStatus, [Status.PASS, Status.FAIL, Status.ERROR, Status.NOT_APPLICABLE]))
    for cs, fs in rows:
        add(f"| {ICON[cs]} {cs.value} | {cstats[cs]} | | {ICON[fs]} {fs.value} | {fstats[fs]} |")
    add("")

    add("## Annex A control status")
    add("")
    add("| Control | Title | Status | Checks |")
    add("|---|---|---|---|")
    for c in controls:
        checks = ", ".join(
            f"**{cid}**" if cid in c.failing_check_ids else cid for cid in c.check_ids
        ) or "—"
        add(f"| A.{c.control_id} | {c.title} | {ICON[c.status]} {c.status.value} | {checks} |")
    add("")

    failing = [f for f in findings if f.status in (Status.FAIL, Status.ERROR)]
    add("## Findings requiring action")
    add("")
    if not failing:
        add("No failing or incomplete checks.")
        add("")
    for f in failing:
        controls_ref = ", ".join(f"A.{c}" for c in f.controls)
        add(f"### {ICON[f.status]} {f.check_id}: {f.title}")
        add("")
        add(f"- **Source:** {f.source}  ")
        add(f"- **Controls:** {controls_ref}  ")
        add(f"- **Result:** {f.detail}  ")
        if f.failing_resources:
            shown = f.failing_resources[:15]
            more = len(f.failing_resources) - len(shown)
            add(f"- **Affected:** {', '.join(f'`{r}`' for r in shown)}" + (f" and {more} more" if more else ""))
        add(f"- **Remediation:** {f.remediation}")
        add("")

    passing = [f for f in findings if f.status in (Status.PASS, Status.NOT_APPLICABLE)]
    if passing:
        add("## Passing and not-applicable checks")
        add("")
        add("| Check | Title | Result |")
        add("|---|---|---|")
        for f in passing:
            add(f"| {f.check_id} | {f.title} | {ICON[f.status]} {f.detail} |")
        add("")

    add("## Evidence")
    add("")
    add("| File | Source | Collected | SHA-256 |")
    add("|---|---|---|---|")
    for e in manifest:
        add(f"| `{e['file']}` | {e['source']} | {e['collected_at']} | `{e['sha256'][:16]}…` |")
    add("")
    add("Verify integrity with `iso27k verify <evidence-dir>`.")
    add("")
    add("## Limitations")
    add("")
    add(DISCLAIMER)
    add("")
    return "\n".join(lines)


RENDERERS = {"md": to_markdown, "json": to_json, "csv": to_csv}
