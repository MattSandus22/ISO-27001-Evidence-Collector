"""Read-only GitHub evidence collector.

Token scopes: a fine-grained token with read access to Administration and
Metadata on the target repos (plus Organization > Administration: read for org
checks), or a classic token with `repo` and `read:org`.
"""

from __future__ import annotations

from typing import Iterator

import requests

from ..models import utcnow

API = "https://api.github.com"


class GitHubCollector:
    def __init__(self, token: str, org: str | None = None, api: str = API, session: requests.Session | None = None):
        self.org = org
        self.api = api.rstrip("/")
        self.s = session or requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "iso27k-evidence",
        })

    # -- HTTP helpers -------------------------------------------------------
    def _get(self, path: str, **params) -> requests.Response:
        return self.s.get(f"{self.api}{path}", params=params or None, timeout=30)

    def _paginate(self, path: str, **params) -> Iterator[dict]:
        url: str | None = f"{self.api}{path}"
        query: dict | None = {"per_page": 100, **params}
        while url:
            r = self.s.get(url, params=query, timeout=30)
            r.raise_for_status()
            yield from r.json()
            url = r.links.get("next", {}).get("url")
            query = None  # next link already carries the query string

    # -- Collection ---------------------------------------------------------
    def collect(self) -> dict:
        snap: dict = {"source": "github", "collected_at": utcnow()}
        if self.org:
            r = self._get(f"/orgs/{self.org}")
            r.raise_for_status()
            o = r.json()
            snap["scope"] = f"org:{o['login']}"
            snap["org"] = {
                "login": o["login"],
                "two_factor_requirement_enabled": o.get("two_factor_requirement_enabled"),
                "default_repository_permission": o.get("default_repository_permission"),
            }
            snap["admins"] = sorted(m["login"] for m in self._paginate(f"/orgs/{self.org}/members", role="admin"))
            repos = self._paginate(f"/orgs/{self.org}/repos", type="all")
        else:
            r = self._get("/user")
            r.raise_for_status()
            snap["scope"] = f"user:{r.json()['login']}"
            snap["org"] = None
            snap["admins"] = None
            repos = self._paginate("/user/repos", affiliation="owner")
        snap["repos"] = [self._repo(repo) for repo in repos]
        return snap

    def _repo(self, r: dict) -> dict:
        owner, name = r["owner"]["login"], r["name"]
        saa = r.get("security_and_analysis") or {}
        secret = (saa.get("secret_scanning") or {}).get("status")
        dep = self._get(f"/repos/{owner}/{name}/vulnerability-alerts").status_code
        return {
            "full_name": r["full_name"],
            "private": r["private"],
            "archived": r.get("archived", False),
            "default_branch": r["default_branch"],
            "branch_protection": self.branch_protection(owner, name, r["default_branch"]),
            "security": {
                "secret_scanning": secret,  # "enabled" | "disabled" | None (not visible)
                "dependabot_alerts": {204: True, 404: False}.get(dep),
            },
        }

    def branch_protection(self, owner: str, name: str, branch: str) -> dict:
        """Merge classic branch protection and repository rulesets into one view."""
        result = {
            "enabled": False,
            "required_approving_review_count": 0,
            "allow_force_pushes": True,
            "sources": [],
        }
        unknown = False

        r = self._get(f"/repos/{owner}/{name}/branches/{branch}/protection")
        if r.status_code == 200:
            p = r.json()
            result["enabled"] = True
            result["sources"].append("branch_protection")
            reviews = p.get("required_pull_request_reviews") or {}
            result["required_approving_review_count"] = reviews.get("required_approving_review_count", 0)
            if not (p.get("allow_force_pushes") or {}).get("enabled", False):
                result["allow_force_pushes"] = False
        elif r.status_code == 403:
            unknown = True  # e.g. private repo on a plan without protection, or missing scope

        rr = self._get(f"/repos/{owner}/{name}/rules/branches/{branch}")
        if rr.status_code == 200 and rr.json():
            result["enabled"] = True
            result["sources"].append("ruleset")
            for rule in rr.json():
                if rule.get("type") == "pull_request":
                    count = (rule.get("parameters") or {}).get("required_approving_review_count", 0)
                    result["required_approving_review_count"] = max(result["required_approving_review_count"], count)
                elif rule.get("type") == "non_fast_forward":
                    result["allow_force_pushes"] = False

        if not result["enabled"] and unknown:
            result["enabled"] = None
        return result
