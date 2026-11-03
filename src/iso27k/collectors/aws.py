"""Read-only AWS evidence collector.

Works with the AWS managed `SecurityAudit` policy. Install with
`pip install "iso27k-evidence[aws]"`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import utcnow

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover - optional dependency
    boto3 = None
    ClientError = Exception


def _mask(key_id: str) -> str:
    """Access key IDs are not secrets, but evidence files should not carry them in full."""
    return f"****{key_id[-4:]}"


def _err(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


def world_ingress(sg: dict) -> list[dict]:
    """Ingress rules that allow 0.0.0.0/0 or ::/0, normalized."""
    rules = []
    for perm in sg.get("IpPermissions", []):
        world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or any(
            r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])
        )
        if world:
            rules.append({
                "protocol": str(perm.get("IpProtocol")),
                "from_port": perm.get("FromPort", 0),
                "to_port": perm.get("ToPort", 65535),
            })
    return rules


class AWSCollector:
    def __init__(self, session=None, regions: list[str] | None = None):
        if boto3 is None and session is None:
            raise RuntimeError('boto3 is required: pip install "iso27k-evidence[aws]"')
        self.session = session or boto3.Session()
        self.regions = regions or [self.session.region_name or "us-east-1"]

    def collect(self) -> dict:
        account = self.session.client("sts").get_caller_identity()["Account"]
        return {
            "source": "aws",
            "collected_at": utcnow(),
            "scope": f"aws:{account}",
            "account_id": account,
            "regions": self.regions,
            "iam": self._iam(),
            "cloudtrail": self._cloudtrail(),
            "s3": self._s3(account),
            "ec2": {r: self._ec2(r) for r in self.regions},
            "guardduty": {r: self._guardduty(r) for r in self.regions},
        }

    def _iam(self) -> dict:
        iam = self.session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if _err(e) != "NoSuchEntity":
                raise
            policy = None

        now = datetime.now(timezone.utc)
        users = []
        for page in iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                name = u["UserName"]
                try:
                    iam.get_login_profile(UserName=name)
                    console = True
                except ClientError as e:
                    if _err(e) != "NoSuchEntity":
                        raise
                    console = False
                keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
                users.append({
                    "name": name,
                    "console_access": console,
                    "mfa_enabled": bool(iam.list_mfa_devices(UserName=name)["MFADevices"]),
                    "access_keys": [
                        {"id": _mask(k["AccessKeyId"]), "status": k["Status"], "age_days": (now - k["CreateDate"]).days}
                        for k in keys
                    ],
                })
        return {
            "account_summary": {"AccountMFAEnabled": summary.get("AccountMFAEnabled", 0)},
            "password_policy": policy,
            "users": users,
        }

    def _cloudtrail(self) -> dict:
        ct = self.session.client("cloudtrail", region_name=self.regions[0])
        trails = []
        for t in ct.describe_trails(includeShadowTrails=False)["trailList"]:
            status = ct.get_trail_status(Name=t["TrailARN"])
            trails.append({
                "name": t["Name"],
                "is_multi_region": t.get("IsMultiRegionTrail", False),
                "is_logging": status.get("IsLogging", False),
                "log_file_validation": t.get("LogFileValidationEnabled", False),
            })
        return {"trails": trails}

    def _s3(self, account: str) -> dict:
        s3 = self.session.client("s3")
        try:
            cfg = self.session.client("s3control", region_name=self.regions[0]).get_public_access_block(AccountId=account)
            account_block = cfg["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if _err(e) != "NoSuchPublicAccessBlockConfiguration":
                raise
            account_block = None
        buckets = []
        for b in s3.list_buckets()["Buckets"]:
            try:
                block = s3.get_public_access_block(Bucket=b["Name"])["PublicAccessBlockConfiguration"]
            except ClientError as e:
                if _err(e) != "NoSuchPublicAccessBlockConfiguration":
                    raise
                block = None
            buckets.append({"name": b["Name"], "public_access_block": block})
        return {"account_public_access_block": account_block, "buckets": buckets}

    def _ec2(self, region: str) -> dict:
        ec2 = self.session.client("ec2", region_name=region)
        groups = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                groups.append({"id": sg["GroupId"], "name": sg["GroupName"], "world_ingress": world_ingress(sg)})
        return {
            "ebs_default_encryption": ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
            "security_groups": groups,
        }

    def _guardduty(self, region: str) -> dict:
        gd = self.session.client("guardduty", region_name=region)
        detectors = gd.list_detectors()["DetectorIds"]
        enabled = any(gd.get_detector(DetectorId=d)["Status"] == "ENABLED" for d in detectors)
        return {"enabled": enabled, "detector_count": len(detectors)}
