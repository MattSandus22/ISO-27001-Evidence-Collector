"""Checks over an AWS evidence snapshot."""

from __future__ import annotations

from . import check
from ..models import CheckResult, Status

MIN_PASSWORD_LENGTH = 14
MAX_ACCESS_KEY_AGE_DAYS = 90
ADMIN_PORTS = (22, 3389)


@check(
    id="AWS-001",
    title="Root account has MFA enabled",
    source="aws",
    controls=["8.2", "8.5"],
    remediation="Sign in as root and assign a hardware or virtual MFA device (IAM > Security credentials).",
)
def root_mfa(snap: dict) -> CheckResult:
    enabled = snap["iam"]["account_summary"].get("AccountMFAEnabled")
    if enabled == 1:
        return CheckResult(Status.PASS, "Root account MFA is enabled.")
    return CheckResult(Status.FAIL, "Root account has no MFA device.", [f"account:{snap['account_id']}"])


@check(
    id="AWS-002",
    title="IAM users with console access have MFA",
    source="aws",
    controls=["8.5"],
    remediation="Enforce MFA for console users, or move human access to IAM Identity Center with MFA.",
)
def console_users_mfa(snap: dict) -> CheckResult:
    console = [u for u in snap["iam"]["users"] if u["console_access"]]
    if not console:
        return CheckResult(Status.NOT_APPLICABLE, "No IAM users have console passwords.")
    failing = [u["name"] for u in console if not u["mfa_enabled"]]
    if failing:
        return CheckResult(Status.FAIL, f"{len(failing)} of {len(console)} console users lack MFA.", failing)
    return CheckResult(Status.PASS, f"All {len(console)} console users have MFA.")


@check(
    id="AWS-003",
    title=f"Password policy requires {MIN_PASSWORD_LENGTH}+ characters",
    source="aws",
    controls=["5.17"],
    remediation=f"IAM > Account settings > set minimum password length to {MIN_PASSWORD_LENGTH} or more.",
)
def password_policy(snap: dict) -> CheckResult:
    policy = snap["iam"]["password_policy"]
    if policy is None:
        return CheckResult(Status.FAIL, "No account password policy is set (AWS defaults apply).", ["password-policy"])
    length = policy.get("MinimumPasswordLength", 0)
    if length >= MIN_PASSWORD_LENGTH:
        return CheckResult(Status.PASS, f"Minimum password length is {length}.")
    return CheckResult(Status.FAIL, f"Minimum password length is {length}.", ["password-policy"])


@check(
    id="AWS-004",
    title=f"Active access keys rotated within {MAX_ACCESS_KEY_AGE_DAYS} days",
    source="aws",
    controls=["5.17", "5.18"],
    remediation="Rotate or delete stale keys; prefer IAM roles and short-lived credentials.",
)
def access_key_age(snap: dict) -> CheckResult:
    keys = [
        (u["name"], k)
        for u in snap["iam"]["users"]
        for k in u["access_keys"]
        if k["status"] == "Active"
    ]
    if not keys:
        return CheckResult(Status.NOT_APPLICABLE, "No active IAM access keys.")
    failing = [f"{name}:{k['id']} ({k['age_days']}d)" for name, k in keys if k["age_days"] > MAX_ACCESS_KEY_AGE_DAYS]
    if failing:
        return CheckResult(Status.FAIL, f"{len(failing)} of {len(keys)} active keys are older than {MAX_ACCESS_KEY_AGE_DAYS} days.", failing)
    return CheckResult(Status.PASS, f"All {len(keys)} active keys are within {MAX_ACCESS_KEY_AGE_DAYS} days.")


@check(
    id="AWS-005",
    title="Multi-region CloudTrail trail is logging",
    source="aws",
    controls=["8.15"],
    remediation="Create a multi-region trail (ideally an organization trail) and confirm logging is on.",
)
def cloudtrail_multi_region(snap: dict) -> CheckResult:
    trails = snap["cloudtrail"]["trails"]
    good = [t["name"] for t in trails if t["is_multi_region"] and t["is_logging"]]
    if good:
        return CheckResult(Status.PASS, f"Logging multi-region trail(s): {', '.join(good)}.")
    return CheckResult(Status.FAIL, "No multi-region trail is actively logging.", [t["name"] for t in trails] or ["cloudtrail"])


@check(
    id="AWS-006",
    title="CloudTrail log file validation enabled",
    source="aws",
    controls=["8.15"],
    remediation="Enable log file integrity validation on every trail.",
)
def cloudtrail_validation(snap: dict) -> CheckResult:
    trails = snap["cloudtrail"]["trails"]
    if not trails:
        return CheckResult(Status.FAIL, "No CloudTrail trails exist.", ["cloudtrail"])
    failing = [t["name"] for t in trails if not t["log_file_validation"]]
    if failing:
        return CheckResult(Status.FAIL, f"{len(failing)} trail(s) lack log file validation.", failing)
    return CheckResult(Status.PASS, f"All {len(trails)} trail(s) validate log file integrity.")


@check(
    id="AWS-007",
    title="S3 Block Public Access enforced",
    source="aws",
    controls=["8.3"],
    remediation="Turn on all four Block Public Access settings at the account level, or per bucket.",
)
def s3_public_access(snap: dict) -> CheckResult:
    s3 = snap["s3"]
    account_block = s3.get("account_public_access_block")
    if account_block and all(account_block.values()):
        return CheckResult(Status.PASS, "Account-level S3 Block Public Access is fully enabled.")
    buckets = s3["buckets"]
    if not buckets:
        return CheckResult(Status.NOT_APPLICABLE, "No S3 buckets.")
    failing = [
        b["name"] for b in buckets
        if not (b["public_access_block"] and all(b["public_access_block"].values()))
    ]
    if failing:
        return CheckResult(Status.FAIL, f"{len(failing)} of {len(buckets)} buckets are not fully blocked from public access.", failing)
    return CheckResult(Status.PASS, f"All {len(buckets)} buckets block public access.")


@check(
    id="AWS-008",
    title="EBS encryption by default enabled",
    source="aws",
    controls=["8.24"],
    remediation="EC2 > Settings > Data protection and security > enable 'Always encrypt new EBS volumes' in each region.",
)
def ebs_default_encryption(snap: dict) -> CheckResult:
    regions = snap["ec2"]
    failing = [r for r, data in regions.items() if not data["ebs_default_encryption"]]
    if failing:
        return CheckResult(Status.FAIL, f"EBS default encryption is off in {len(failing)} region(s).", failing)
    return CheckResult(Status.PASS, f"EBS default encryption is on in all {len(regions)} region(s) checked.")


def _exposes_admin_port(rule: dict) -> list[int]:
    if rule["protocol"] == "-1":
        return list(ADMIN_PORTS)
    if rule["protocol"] not in ("tcp", "6"):
        return []
    lo, hi = rule.get("from_port", 0), rule.get("to_port", 65535)
    return [p for p in ADMIN_PORTS if lo <= p <= hi]


@check(
    id="AWS-009",
    title="No security group allows SSH/RDP from the internet",
    source="aws",
    controls=["8.20"],
    remediation="Restrict ports 22/3389 to known CIDRs or use SSM Session Manager instead of open admin ports.",
)
def open_admin_ports(snap: dict) -> CheckResult:
    failing = []
    total = 0
    for region, data in snap["ec2"].items():
        for sg in data["security_groups"]:
            total += 1
            ports = sorted({p for rule in sg["world_ingress"] for p in _exposes_admin_port(rule)})
            if ports:
                failing.append(f"{region}/{sg['id']} ({sg['name']}) ports {','.join(map(str, ports))}")
    if failing:
        return CheckResult(Status.FAIL, f"{len(failing)} security group(s) expose admin ports to 0.0.0.0/0 or ::/0.", failing)
    return CheckResult(Status.PASS, f"None of {total} security groups expose SSH/RDP to the internet.")


@check(
    id="AWS-010",
    title="GuardDuty enabled",
    source="aws",
    controls=["8.16"],
    remediation="Enable GuardDuty in every region in scope (delegated admin via AWS Organizations is recommended).",
)
def guardduty_enabled(snap: dict) -> CheckResult:
    regions = snap["guardduty"]
    failing = [r for r, data in regions.items() if not data["enabled"]]
    if failing:
        return CheckResult(Status.FAIL, f"GuardDuty is not enabled in {len(failing)} region(s).", failing)
    return CheckResult(Status.PASS, f"GuardDuty is enabled in all {len(regions)} region(s) checked.")
