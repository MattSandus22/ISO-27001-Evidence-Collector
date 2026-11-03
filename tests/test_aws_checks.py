import pytest

from iso27k.checks import REGISTRY, run_check
from iso27k.checks.aws_checks import _exposes_admin_port
from iso27k.collectors.aws import world_ingress
from iso27k.models import Status


def result(check_id, snap):
    return run_check(REGISTRY[check_id], snap)


def test_fixture_expected_statuses(aws_snap):
    expected = {
        "AWS-001": Status.PASS,
        "AWS-002": Status.FAIL,
        "AWS-003": Status.FAIL,
        "AWS-004": Status.FAIL,
        "AWS-005": Status.PASS,
        "AWS-006": Status.PASS,
        "AWS-007": Status.FAIL,
        "AWS-008": Status.FAIL,
        "AWS-009": Status.FAIL,
        "AWS-010": Status.PASS,
    }
    for cid, status in expected.items():
        assert result(cid, aws_snap).status == status, cid


def test_inactive_keys_ignored(aws_snap):
    f = result("AWS-004", aws_snap)
    assert f.failing_resources == ["ci-deploy:****Q7XA (214d)"]


def test_account_level_s3_block_overrides_buckets(aws_snap):
    aws_snap["s3"]["account_public_access_block"] = {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    }
    assert result("AWS-007", aws_snap).status == Status.PASS


def test_no_password_policy_fails(aws_snap):
    aws_snap["iam"]["password_policy"] = None
    assert result("AWS-003", aws_snap).status == Status.FAIL


@pytest.mark.parametrize("rule,ports", [
    ({"protocol": "tcp", "from_port": 22, "to_port": 22}, [22]),
    ({"protocol": "tcp", "from_port": 0, "to_port": 65535}, [22, 3389]),
    ({"protocol": "-1"}, [22, 3389]),
    ({"protocol": "tcp", "from_port": 443, "to_port": 443}, []),
    ({"protocol": "udp", "from_port": 0, "to_port": 65535}, []),
])
def test_admin_port_detection(rule, ports):
    assert _exposes_admin_port(rule) == ports


def test_world_ingress_normalization():
    sg = {"IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
    ]}
    assert world_ingress(sg) == [{"protocol": "tcp", "from_port": 3389, "to_port": 3389}]
