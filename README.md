# iso27001-evidence-collector

Collect technical evidence from **GitHub** and **AWS**, map it to **ISO/IEC 27001:2022 Annex A** controls, and produce an auditor-friendly gap report with tamper-evident evidence files.

```
collect (read-only APIs) ──▶ evidence/*.json + SHA-256 manifest ──▶ checks ──▶ Annex A rollup ──▶ report.md / .csv / .json
```

Built to answer the question an ISMS lead or internal auditor actually asks: *"For the technological controls we claim in our Statement of Applicability, what does the live configuration show right now, and can I trust that evidence?"*

## Why this design

| Decision | Reason |
|---|---|
| **Collectors are read-only** | Only `GET` / `Describe` / `List` calls. Runs safely under AWS `SecurityAudit` and a read-scoped GitHub token. |
| **Checks are pure functions over stored evidence** | Every finding can be reproduced from the evidence file alone, months later, without API access. That is what makes it audit evidence and not just a scan. |
| **SHA-256 manifest** | `iso27k verify` proves evidence files were not edited after collection. Assessment refuses to run on tampered evidence. |
| **Many-to-many control mapping** | One check can support several controls (e.g. branch protection → A.8.4 and A.8.32), mirroring how auditors reuse evidence. |
| **"Unknown" is never "Pass"** | If a token can't see a setting, the check returns `ERROR` and the control shows *Incomplete evidence*, never a false pass. |
| **Secrets stay out of evidence** | AWS access key IDs are masked to their last four characters. |

## Quick start (no credentials needed)

```bash
git clone https://github.com/MattSandus22/ISO-27001-Evidence-Collector.git
cd ISO-27001-Evidence-Collector
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Load the sample evidence for a fictional company and assess it
iso27k ingest examples/fixtures/github-acme.json --out evidence
iso27k ingest examples/fixtures/aws-acme.json --out evidence
iso27k verify evidence
iso27k assess evidence -o report.md
```

See [`examples/sample-report.md`](examples/sample-report.md) for the output and [`examples/sample-report.csv`](examples/sample-report.csv) for the SoA-friendly CSV.

## Running against real systems

### GitHub

```bash
export GITHUB_TOKEN=ghp_...            # classic: repo + read:org, or fine-grained: Administration (read)
iso27k collect github --org my-org     # an organization
iso27k collect github                  # or: repositories you own
```

Both classic branch protection and newer repository rulesets are recognized.

### AWS

```bash
pip install -e ".[aws]"
iso27k collect aws --profile audit --regions us-east-1,us-west-2
```

Attach the AWS managed `SecurityAudit` policy to the role or user you collect with.

### Assess and report

```bash
iso27k assess evidence -o report.md            # Markdown
iso27k assess evidence --format csv -o soa.csv  # control rows for a Statement of Applicability
iso27k assess evidence --format json            # machine-readable
iso27k assess evidence --fail-on-gap            # exit 1 on any gap, for CI pipelines
```

When several snapshots exist for the same source, the most recent one is assessed; older snapshots stay in the store as history.

## Check catalog

| Check | Source | Annex A | What it tests |
|---|---|---|---|
| GH-001 | GitHub | 5.17, 8.5 | Organization requires 2FA |
| GH-002 | GitHub | 8.2 | Three or fewer organization owners |
| GH-003 | GitHub | 5.15, 5.18 | Base member permission is read or none |
| GH-004 | GitHub | 8.4, 8.32 | Default branch protected (classic rule or ruleset) |
| GH-005 | GitHub | 8.25, 8.32 | At least one approving review before merge |
| GH-006 | GitHub | 8.32 | Force pushes blocked on default branch |
| GH-007 | GitHub | 5.17, 8.28 | Secret scanning enabled |
| GH-008 | GitHub | 8.8 | Dependabot vulnerability alerts enabled |
| AWS-001 | AWS | 8.2, 8.5 | Root account MFA |
| AWS-002 | AWS | 8.5 | Console users have MFA |
| AWS-003 | AWS | 5.17 | Password policy minimum length ≥ 14 |
| AWS-004 | AWS | 5.17, 5.18 | Active access keys rotated within 90 days |
| AWS-005 | AWS | 8.15 | Multi-region CloudTrail trail is logging |
| AWS-006 | AWS | 8.15 | CloudTrail log file validation |
| AWS-007 | AWS | 8.3 | S3 Block Public Access (account or bucket level) |
| AWS-008 | AWS | 8.24 | EBS encryption by default, per region |
| AWS-009 | AWS | 8.20 | No SSH/RDP open to 0.0.0.0/0 or ::/0 |
| AWS-010 | AWS | 8.16 | GuardDuty enabled, per region |

Run `iso27k list-checks` for the live list. Thresholds (admin count, key age, password length) are constants at the top of each check module.

### Control status logic

| Status | Meaning |
|---|---|
| Evidence supports | Every applicable check passed |
| Gap identified | At least one check failed |
| Incomplete evidence | No failures, but at least one check could not read its evidence |
| Not assessed | No applicable automated check (needs manual evidence) |

## Adding a check

```python
# src/iso27k/checks/github_checks.py
@check(
    id="GH-009",
    title="Signed commits required on default branch",
    source="github",
    controls=["8.32"],
    remediation="Add a 'Require signed commits' rule to the default-branch ruleset.",
)
def signed_commits(snap: dict) -> CheckResult:
    ...
```

The test suite fails if a check references a control that isn't in `src/iso27k/data/annex_a.yaml`.

## Project layout

```
src/iso27k/
  collectors/   github.py, aws.py      live, read-only evidence collection
  checks/       github_checks.py, aws_checks.py   pure checks + registry
  data/         annex_a.yaml           ISO 27001:2022 controls in scope
  evidence.py   hashed evidence store and integrity verification
  assess.py     run checks, roll findings up to controls
  report.py     Markdown / CSV / JSON output
  cli.py        iso27k command
examples/       fictional sample evidence and generated reports
tests/          pytest suite (no network required)
```

## Limitations

- Covers 15 of the 93 Annex A controls, all technological or access-related. Organizational, people and physical controls need documented, manual evidence.
- A passing check shows a configuration at one point in time. ISO 27001 conformity also requires policy, ownership, risk treatment and evidence that controls operate over the audit period.
- Control titles come from ISO/IEC 27001:2022 Annex A; the standard text itself is not reproduced. Consult the licensed standard for control requirements.

## Roadmap

- Azure and Google Workspace collectors
- Okta / Entra ID MFA and joiner-mover-leaver evidence (A.5.16, A.5.18)
- OSCAL assessment-results output
- Mapping overlays for SOC 2 and NIST CSF 2.0

## License

MIT. See [LICENSE](LICENSE).
