"""Evidence store with a SHA-256 manifest.

Every snapshot is written as canonical JSON and its hash recorded in
manifest.json, so an auditor can confirm the evidence behind a report was not
altered after collection (`iso27k verify`).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import __version__

MANIFEST = "manifest.json"


class IntegrityError(Exception):
    pass


def _canonical(snapshot: dict) -> bytes:
    return (json.dumps(snapshot, indent=2, sort_keys=True, default=str) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_manifest(directory: Path) -> list[dict]:
    path = directory / MANIFEST
    return json.loads(path.read_text()) if path.exists() else []


def save_snapshot(snapshot: dict, directory: str | Path) -> Path:
    for key in ("source", "collected_at"):
        if key not in snapshot:
            raise ValueError(f"Snapshot is missing required key '{key}'")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = snapshot["collected_at"].replace(":", "").replace("-", "").replace("+0000", "Z")
    path = directory / f"{snapshot['source']}-{stamp}.json"
    data = _canonical(snapshot)
    path.write_bytes(data)

    manifest = [e for e in _read_manifest(directory) if e["file"] != path.name]
    manifest.append({
        "file": path.name,
        "sha256": sha256(data),
        "source": snapshot["source"],
        "scope": snapshot.get("scope", ""),
        "collected_at": snapshot["collected_at"],
        "tool_version": __version__,
    })
    (directory / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    return path


def verify(directory: str | Path) -> list[tuple[str, bool]]:
    directory = Path(directory)
    results = []
    for entry in _read_manifest(directory):
        path = directory / entry["file"]
        ok = path.exists() and sha256(path.read_bytes()) == entry["sha256"]
        results.append((entry["file"], ok))
    return results


def load_evidence(directory: str | Path) -> tuple[list[dict], list[dict]]:
    """Return (latest snapshot per source, manifest entries used). Raises on tampering."""
    directory = Path(directory)
    manifest = _read_manifest(directory)
    if not manifest:
        raise FileNotFoundError(f"No {MANIFEST} in {directory}; collect or ingest evidence first.")
    bad = [f for f, ok in verify(directory) if not ok]
    if bad:
        raise IntegrityError(f"Evidence hash mismatch or missing file: {', '.join(bad)}")

    latest: dict[str, dict] = {}
    for entry in manifest:
        current = latest.get(entry["source"])
        if current is None or entry["collected_at"] > current["collected_at"]:
            latest[entry["source"]] = entry
    used = sorted(latest.values(), key=lambda e: e["source"])
    snapshots = [json.loads((directory / e["file"]).read_text()) for e in used]
    return snapshots, used
