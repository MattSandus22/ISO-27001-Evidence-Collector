"""Checks over a GitHub evidence snapshot."""

from __future__ import annotations

from . import check
from ..models import CheckResult, Status

MAX_ORG_ADMINS = 3
ALLOWED_BASE_PERMISSIONS = {"none", "read"}


def _active_repos(snap: dict) -> list[dict]:
    return [r for r in snap["repos"] if not r.get("archived")]


def _repo_check(snap: dict, predicate, unknown, ok_msg: str, fail_msg: str) -> CheckResult:
    """Shared logic for per-repo checks.

    predicate(repo) -> True if compliant; unknown(repo) -> True if evidence is missing.
    """
    repos = _active_repos(snap)
    if not repos:
        return CheckResult(Status.NOT_APPLICABLE, "No active repositories in scope.")
    failing = [r["full_name"] for r in repos if not unknown(r) and not predicate(r)]
    missing = [r["full_name"] for r in repos if unknown(r)]
    if failing:
        return CheckResult(Status.FAIL, f"{len(failing)} of {len(repos)} repositories {fail_msg}.", failing)
    if missing:
        return CheckResult(
            Status.ERROR,
            f"Could not read evidence for {len(missing)} repositories (token may lack admin scope).",
            missing,
        )
    return CheckResult(Status.PASS, f"All {len(repos)} active repositories {ok_msg}.")


@check(
    id="GH-001",
    title="Organization requires two-factor authentication",
    source="github",
    controls=["5.17", "8.5"],
    remediation="Organization settings > Authentication security > Require two-factor authentication.",
)
def org_requires_2fa(snap: dict) -> CheckResult:
    org = snap.get("org")
    if not org:
        return CheckResult(Status.NOT_APPLICABLE, "Scope is a personal account, not an organization.")
    value = org.get("two_factor_requirement_enabled")
    if value is None:
        return CheckResult(Status.ERROR, "2FA requirement not visible; token needs admin:org (read) scope.")
    if value:
        return CheckResult(Status.PASS, f"Organization {org['login']} enforces 2FA for all members.")
    return CheckResult(Status.FAIL, f"Organization {org['login']} does not require 2FA.", [org["login"]])


@check(
    id="GH-002",
    title=f"Organization owners limited to {MAX_ORG_ADMINS} or fewer",
    source="github",
    controls=["8.2"],
    remediation="Review organization owners and downgrade accounts that do not need owner rights.",
)
def org_admin_count(snap: dict) -> CheckResult:
    if not snap.get("org"):
        return CheckResult(Status.NOT_APPLICABLE, "Scope is a personal account, not an organization.")
    admins = snap["admins"]
    if admins is None:
        return CheckResult(Status.ERROR, "Could not list organization owners.")
    if len(admins) <= MAX_ORG_ADMINS:
        return CheckResult(Status.PASS, f"{len(admins)} organization owner(s): {', '.join(admins)}.")
    return CheckResult(
        Status.FAIL,
        f"{len(admins)} organization owners exceeds the limit of {MAX_ORG_ADMINS}.",
        admins,
    )


@check(
    id="GH-003",
    title="Default member repository permission is read or none",
    source="github",
    controls=["5.15", "5.18"],
    remediation="Organization settings > Member privileges > Base permissions: set to Read or No permission.",
)
def org_base_permission(snap: dict) -> CheckResult:
    org = snap.get("org")
    if not org:
        return CheckResult(Status.NOT_APPLICABLE, "Scope is a personal account, not an organization.")
    perm = org.get("default_repository_permission")
    if perm is None:
        return CheckResult(Status.ERROR, "Base permission not visible to this token.")
    if perm in ALLOWED_BASE_PERMISSIONS:
        return CheckResult(Status.PASS, f"Base permission is '{perm}' (least privilege).")
    return CheckResult(Status.FAIL, f"Base permission is '{perm}'; members get more access than needed.", [org["login"]])


@check(
    id="GH-004",
    title="Default branch is protected",
    source="github",
    controls=["8.4", "8.32"],
    remediation="Add a branch protection rule or repository ruleset targeting the default branch.",
)
def default_branch_protected(snap: dict) -> CheckResult:
    return _repo_check(
        snap,
        predicate=lambda r: r["branch_protection"]["enabled"] is True,
        unknown=lambda r: r["branch_protection"]["enabled"] is None,
        ok_msg="protect their default branch",
        fail_msg="have an unprotected default branch",
    )


@check(
    id="GH-005",
    title="Pull request review required before merge",
    source="github",
    controls=["8.25", "8.32"],
    remediation="Require at least one approving review in the branch protection rule or ruleset.",
)
def pr_review_required(snap: dict) -> CheckResult:
    return _repo_check(
        snap,
        predicate=lambda r: r["branch_protection"]["required_approving_review_count"] >= 1,
        unknown=lambda r: r["branch_protection"]["enabled"] is None,
        ok_msg="require at least one approving review",
        fail_msg="allow merging without review",
    )


@check(
    id="GH-006",
    title="Force pushes blocked on default branch",
    source="github",
    controls=["8.32"],
    remediation="Disable 'Allow force pushes' or add a 'Block force pushes' ruleset rule.",
)
def force_push_blocked(snap: dict) -> CheckResult:
    return _repo_check(
        snap,
        predicate=lambda r: r["branch_protection"]["allow_force_pushes"] is False,
        unknown=lambda r: r["branch_protection"]["enabled"] is None,
        ok_msg="block force pushes to the default branch",
        fail_msg="allow history to be rewritten on the default branch",
    )


@check(
    id="GH-007",
    title="Secret scanning enabled",
    source="github",
    controls=["5.17", "8.28"],
    remediation="Repository settings > Code security > enable Secret scanning (and push protection).",
)
def secret_scanning(snap: dict) -> CheckResult:
    return _repo_check(
        snap,
        predicate=lambda r: r["security"]["secret_scanning"] == "enabled",
        unknown=lambda r: r["security"]["secret_scanning"] is None,
        ok_msg="have secret scanning enabled",
        fail_msg="have secret scanning disabled",
    )


@check(
    id="GH-008",
    title="Dependabot vulnerability alerts enabled",
    source="github",
    controls=["8.8"],
    remediation="Repository settings > Code security > enable Dependabot alerts.",
)
def dependabot_alerts(snap: dict) -> CheckResult:
    return _repo_check(
        snap,
        predicate=lambda r: r["security"]["dependabot_alerts"] is True,
        unknown=lambda r: r["security"]["dependabot_alerts"] is None,
        ok_msg="have Dependabot alerts enabled",
        fail_msg="have Dependabot alerts disabled",
    )
