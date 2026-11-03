# ISO/IEC 27001:2022 Technical Evidence Report

Generated 2026-11-03T20:48:01+00:00 by iso27k-evidence v0.1.0. Scope: `aws:111122223333`, `org:acme-demo`.

## Summary

| Controls | Count | | Checks | Count |
|---|---|---|---|---|
| ✅ Evidence supports | 3 | | ✅ PASS | 6 |
| ❌ Gap identified | 12 | | ❌ FAIL | 12 |
| ⚠️ Incomplete evidence | 0 | | ⚠️ ERROR | 0 |
| ➖ Not assessed | 0 | | ➖ N/A | 0 |

## Annex A control status

| Control | Title | Status | Checks |
|---|---|---|---|
| A.5.15 | Access control | ❌ Gap identified | **GH-003** |
| A.5.17 | Authentication information | ❌ Gap identified | **AWS-003**, **AWS-004**, GH-001, **GH-007** |
| A.5.18 | Access rights | ❌ Gap identified | **AWS-004**, **GH-003** |
| A.8.2 | Privileged access rights | ✅ Evidence supports | AWS-001, GH-002 |
| A.8.3 | Information access restriction | ❌ Gap identified | **AWS-007** |
| A.8.4 | Access to source code | ❌ Gap identified | **GH-004** |
| A.8.5 | Secure authentication | ❌ Gap identified | AWS-001, **AWS-002**, GH-001 |
| A.8.8 | Management of technical vulnerabilities | ❌ Gap identified | **GH-008** |
| A.8.15 | Logging | ✅ Evidence supports | AWS-005, AWS-006 |
| A.8.16 | Monitoring activities | ✅ Evidence supports | AWS-010 |
| A.8.20 | Networks security | ❌ Gap identified | **AWS-009** |
| A.8.24 | Use of cryptography | ❌ Gap identified | **AWS-008** |
| A.8.25 | Secure development life cycle | ❌ Gap identified | **GH-005** |
| A.8.28 | Secure coding | ❌ Gap identified | **GH-007** |
| A.8.32 | Change management | ❌ Gap identified | **GH-004**, **GH-005**, **GH-006** |

## Findings requiring action

### ❌ AWS-002: IAM users with console access have MFA

- **Source:** aws  
- **Controls:** A.8.5  
- **Result:** 1 of 2 console users lack MFA.  
- **Affected:** `contractor-temp`
- **Remediation:** Enforce MFA for console users, or move human access to IAM Identity Center with MFA.

### ❌ AWS-003: Password policy requires 14+ characters

- **Source:** aws  
- **Controls:** A.5.17  
- **Result:** Minimum password length is 8.  
- **Affected:** `password-policy`
- **Remediation:** IAM > Account settings > set minimum password length to 14 or more.

### ❌ AWS-004: Active access keys rotated within 90 days

- **Source:** aws  
- **Controls:** A.5.17, A.5.18  
- **Result:** 1 of 2 active keys are older than 90 days.  
- **Affected:** `ci-deploy:****Q7XA (214d)`
- **Remediation:** Rotate or delete stale keys; prefer IAM roles and short-lived credentials.

### ❌ AWS-007: S3 Block Public Access enforced

- **Source:** aws  
- **Controls:** A.8.3  
- **Result:** 1 of 2 buckets are not fully blocked from public access.  
- **Affected:** `acme-marketing-site`
- **Remediation:** Turn on all four Block Public Access settings at the account level, or per bucket.

### ❌ AWS-008: EBS encryption by default enabled

- **Source:** aws  
- **Controls:** A.8.24  
- **Result:** EBS default encryption is off in 1 region(s).  
- **Affected:** `us-west-2`
- **Remediation:** EC2 > Settings > Data protection and security > enable 'Always encrypt new EBS volumes' in each region.

### ❌ AWS-009: No security group allows SSH/RDP from the internet

- **Source:** aws  
- **Controls:** A.8.20  
- **Result:** 1 security group(s) expose admin ports to 0.0.0.0/0 or ::/0.  
- **Affected:** `us-east-1/sg-0e4f5a6b (bastion) ports 22`
- **Remediation:** Restrict ports 22/3389 to known CIDRs or use SSM Session Manager instead of open admin ports.

### ❌ GH-003: Default member repository permission is read or none

- **Source:** github  
- **Controls:** A.5.15, A.5.18  
- **Result:** Base permission is 'write'; members get more access than needed.  
- **Affected:** `acme-demo`
- **Remediation:** Organization settings > Member privileges > Base permissions: set to Read or No permission.

### ❌ GH-004: Default branch is protected

- **Source:** github  
- **Controls:** A.8.4, A.8.32  
- **Result:** 1 of 3 repositories have an unprotected default branch.  
- **Affected:** `acme-demo/infra-scripts`
- **Remediation:** Add a branch protection rule or repository ruleset targeting the default branch.

### ❌ GH-005: Pull request review required before merge

- **Source:** github  
- **Controls:** A.8.25, A.8.32  
- **Result:** 2 of 3 repositories allow merging without review.  
- **Affected:** `acme-demo/web-frontend`, `acme-demo/infra-scripts`
- **Remediation:** Require at least one approving review in the branch protection rule or ruleset.

### ❌ GH-006: Force pushes blocked on default branch

- **Source:** github  
- **Controls:** A.8.32  
- **Result:** 1 of 3 repositories allow history to be rewritten on the default branch.  
- **Affected:** `acme-demo/infra-scripts`
- **Remediation:** Disable 'Allow force pushes' or add a 'Block force pushes' ruleset rule.

### ❌ GH-007: Secret scanning enabled

- **Source:** github  
- **Controls:** A.5.17, A.8.28  
- **Result:** 1 of 3 repositories have secret scanning disabled.  
- **Affected:** `acme-demo/infra-scripts`
- **Remediation:** Repository settings > Code security > enable Secret scanning (and push protection).

### ❌ GH-008: Dependabot vulnerability alerts enabled

- **Source:** github  
- **Controls:** A.8.8  
- **Result:** 1 of 3 repositories have Dependabot alerts disabled.  
- **Affected:** `acme-demo/web-frontend`
- **Remediation:** Repository settings > Code security > enable Dependabot alerts.

## Passing and not-applicable checks

| Check | Title | Result |
|---|---|---|
| AWS-001 | Root account has MFA enabled | ✅ Root account MFA is enabled. |
| AWS-005 | Multi-region CloudTrail trail is logging | ✅ Logging multi-region trail(s): org-trail. |
| AWS-006 | CloudTrail log file validation enabled | ✅ All 1 trail(s) validate log file integrity. |
| AWS-010 | GuardDuty enabled | ✅ GuardDuty is enabled in all 2 region(s) checked. |
| GH-001 | Organization requires two-factor authentication | ✅ Organization acme-demo enforces 2FA for all members. |
| GH-002 | Organization owners limited to 3 or fewer | ✅ 2 organization owner(s): alice, bob. |

## Evidence

| File | Source | Collected | SHA-256 |
|---|---|---|---|
| `aws-20261103T150500Z.json` | aws | 2026-11-03T15:05:00+00:00 | `b6a1ccb7ecf46e5d…` |
| `github-20261103T150000Z.json` | github | 2026-11-03T15:00:00+00:00 | `85c313bab9cb605f…` |

Verify integrity with `iso27k verify <evidence-dir>`.

## Limitations

Automated checks show whether specific technical configurations are in place at the time of collection. They support, but do not by themselves demonstrate, conformity with ISO/IEC 27001. Each control also requires documented policy, ownership and operating evidence reviewed by a qualified auditor.
