"""Core data types shared by checks, assessment and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"            # evidence missing or unreadable
    NOT_APPLICABLE = "N/A"     # check does not apply to this scope


class ControlStatus(str, Enum):
    SUPPORTED = "Evidence supports"
    GAP = "Gap identified"
    INCOMPLETE = "Incomplete evidence"
    NOT_ASSESSED = "Not assessed"


@dataclass
class CheckResult:
    """What a check function returns."""

    status: Status
    detail: str
    failing_resources: list[str] = field(default_factory=list)


@dataclass
class Finding:
    check_id: str
    title: str
    source: str
    status: Status
    detail: str
    controls: list[str]
    remediation: str
    failing_resources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class ControlResult:
    control_id: str
    title: str
    theme: str
    status: ControlStatus
    check_ids: list[str]
    failing_check_ids: list[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d
