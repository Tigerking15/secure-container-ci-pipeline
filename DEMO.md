# Demo runbook

Prereq: Docker Desktop running. Open PowerShell in the repo folder:

    cd "C:\Users\Victus\OneDrive\Desktop\Devops lab ca\secure-container-ci-pipeline"

(First run pulls images: conftest, trivy, syft. Do one dry run beforehand.)

## One command, everything
    ./scripts/demo.ps1 -Scenario all -Pause      # Enter between scenarios

## Step by step

| # | Say | Command | Expected |
|---|-----|---------|----------|
| 1 | Policy is code, and the code is tested | `./scripts/demo.ps1 -Scenario tests` | `6 tests, 6 passed` |
| 2 | SUCCESS: signed image, modern base, 0 critical CVEs | `./scripts/demo.ps1 -Scenario pass` | facts: signed true, critical 0 -> `POLICY GATE: PASSED` |
| 3 | FAIL 1: same image but unsigned | `./scripts/demo.ps1 -Scenario unsigned` | `FAIL ... image is not signed with Cosign` -> `BLOCKED` |
| 4 | FAIL 2: signed, but old base python:3.8 | `./scripts/demo.ps1 -Scenario critical` | critical 20 -> `FAIL ... 20 CRITICAL severity CVE(s)` -> `BLOCKED` |

## Show the artifacts
    Get-Content demo-out\pass\facts.json
    (Get-Content demo-out\pass\sbom.json -Raw | ConvertFrom-Json).components | Select -First 10 name,version
    Get-Content demo-out\critical\facts.json

## Show the policy and the test (30 seconds)
    Get-Content policy\deny.rego
    Get-Content policy\deny_test.rego | Select -First 20

## Live break-the-policy (optional, shows the unit tests catch it)
    (Get-Content policy\deny.rego) -replace 'critical_count > 0','critical_count > 99' | Set-Content policy\deny.rego
    ./scripts/demo.ps1 -Scenario tests          # tests FAIL
    git checkout policy/deny.rego               # only if this folder is a git repo; otherwise re-copy the file

## Real signing (GitHub Actions, needs the repo pushed)
1. Open the repo > Actions > latest run: show the four jobs.
2. Open a PR to see the sticky security comment.
3. Verify the published image from any machine:

        cosign verify --certificate-identity-regexp "^https://github.com/Tigerking15/secure-container-ci-pipeline/" --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/tigerking15/secure-container-ci-pipeline@<digest>

## Notes
- Local runs simulate the signature flag; real Cosign signing happens only in CI.
- `app/Dockerfile` in the repo uses `FROM python:3.8`, which has 20 CRITICAL CVEs, so the real CI gate will BLOCK on it. Use that as the failure demo, or switch it to `python:3.12-slim` for a green CI run.
- Outputs are written to `demo-out/` (safe to delete).
