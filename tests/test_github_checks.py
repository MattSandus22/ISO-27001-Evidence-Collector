from iso27k.checks import REGISTRY, run_check
from iso27k.collectors.github import GitHubCollector
from iso27k.models import Status


def result(check_id, snap):
    return run_check(REGISTRY[check_id], snap)


def test_org_2fa_pass_and_fail(github_snap):
    assert result("GH-001", github_snap).status == Status.PASS
    github_snap["org"]["two_factor_requirement_enabled"] = False
    assert result("GH-001", github_snap).status == Status.FAIL


def test_org_2fa_unknown_is_error(github_snap):
    github_snap["org"]["two_factor_requirement_enabled"] = None
    assert result("GH-001", github_snap).status == Status.ERROR


def test_org_checks_not_applicable_for_personal_scope(github_snap):
    github_snap["org"] = None
    github_snap["admins"] = None
    for cid in ("GH-001", "GH-002", "GH-003"):
        assert result(cid, github_snap).status == Status.NOT_APPLICABLE


def test_admin_count_limit(github_snap):
    assert result("GH-002", github_snap).status == Status.PASS
    github_snap["admins"] = ["a", "b", "c", "d"]
    assert result("GH-002", github_snap).status == Status.FAIL


def test_base_permission_write_fails(github_snap):
    assert result("GH-003", github_snap).status == Status.FAIL


def test_archived_repos_are_excluded(github_snap):
    f = result("GH-004", github_snap)
    assert f.status == Status.FAIL
    assert f.failing_resources == ["acme-demo/infra-scripts"]
    assert "acme-demo/legacy-portal" not in f.failing_resources


def test_review_requirement(github_snap):
    f = result("GH-005", github_snap)
    assert f.status == Status.FAIL
    assert set(f.failing_resources) == {"acme-demo/web-frontend", "acme-demo/infra-scripts"}


def test_unknown_protection_reports_error_not_pass(github_snap):
    for repo in github_snap["repos"]:
        repo["branch_protection"]["enabled"] = None
    assert result("GH-004", github_snap).status == Status.ERROR


def test_missing_field_becomes_error(github_snap):
    del github_snap["repos"][0]["security"]
    assert result("GH-007", github_snap).status == Status.ERROR


# --- collector merge logic, with a fake HTTP session -----------------------

class FakeResp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.links = {}

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}

    def get(self, url, params=None, timeout=None):
        for suffix, resp in self.routes.items():
            if url.endswith(suffix):
                return resp
        return FakeResp(404, {})


def test_ruleset_protection_is_recognized():
    session = FakeSession({
        "/branches/main/protection": FakeResp(404, {}),
        "/rules/branches/main": FakeResp(200, [
            {"type": "pull_request", "parameters": {"required_approving_review_count": 1}},
            {"type": "non_fast_forward"},
        ]),
    })
    bp = GitHubCollector("t", session=session).branch_protection("o", "r", "main")
    assert bp["enabled"] is True
    assert bp["required_approving_review_count"] == 1
    assert bp["allow_force_pushes"] is False
    assert bp["sources"] == ["ruleset"]


def test_forbidden_protection_is_unknown():
    session = FakeSession({
        "/branches/main/protection": FakeResp(403, {}),
        "/rules/branches/main": FakeResp(200, []),
    })
    bp = GitHubCollector("t", session=session).branch_protection("o", "r", "main")
    assert bp["enabled"] is None
