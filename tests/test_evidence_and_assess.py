import json

import pytest

from iso27k.assess import load_controls, run_checks, summarize_controls, unmapped_controls
from iso27k.cli import main
from iso27k.evidence import IntegrityError, load_evidence, save_snapshot, verify
from iso27k.models import ControlStatus


def test_every_check_maps_to_a_known_control():
    assert unmapped_controls() == []


def test_save_and_verify_roundtrip(tmp_path, github_snap):
    path = save_snapshot(github_snap, tmp_path)
    assert verify(tmp_path) == [(path.name, True)]
    snapshots, manifest = load_evidence(tmp_path)
    assert snapshots[0]["scope"] == "org:acme-demo"
    assert manifest[0]["sha256"]


def test_tampering_is_detected(tmp_path, github_snap):
    path = save_snapshot(github_snap, tmp_path)
    data = json.loads(path.read_text())
    data["org"]["two_factor_requirement_enabled"] = True
    data["org"]["default_repository_permission"] = "read"
    path.write_text(json.dumps(data))
    assert verify(tmp_path) == [(path.name, False)]
    with pytest.raises(IntegrityError):
        load_evidence(tmp_path)


def test_latest_snapshot_per_source_wins(tmp_path, github_snap):
    save_snapshot(github_snap, tmp_path)
    newer = dict(github_snap, collected_at="2026-12-01T00:00:00+00:00", scope="org:newer")
    save_snapshot(newer, tmp_path)
    snapshots, _ = load_evidence(tmp_path)
    assert [s["scope"] for s in snapshots] == ["org:newer"]


def test_control_rollup(github_snap, aws_snap):
    findings = run_checks([github_snap, aws_snap])
    controls = {c.control_id: c for c in summarize_controls(findings, load_controls())}
    assert controls["8.15"].status == ControlStatus.SUPPORTED   # CloudTrail passes
    assert controls["8.16"].status == ControlStatus.SUPPORTED   # GuardDuty passes
    assert controls["8.20"].status == ControlStatus.GAP         # open SSH
    assert controls["8.32"].status == ControlStatus.GAP         # unprotected branch
    assert "GH-004" in controls["8.4"].failing_check_ids


def test_cli_end_to_end(tmp_path, github_snap, aws_snap, capsys):
    ev = tmp_path / "evidence"
    for name, snap in (("gh.json", github_snap), ("aws.json", aws_snap)):
        (tmp_path / name).write_text(json.dumps(snap))
        assert main(["ingest", str(tmp_path / name), "--out", str(ev)]) == 0
    assert main(["verify", str(ev)]) == 0

    report = tmp_path / "report.md"
    assert main(["assess", str(ev), "-o", str(report)]) == 0
    text = report.read_text()
    assert "A.8.20" in text and "Gap identified" in text and "SHA-256" in text

    assert main(["assess", str(ev), "--fail-on-gap", "--format", "csv", "-o", str(tmp_path / "r.csv")]) == 1
