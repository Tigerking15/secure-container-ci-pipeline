# Secure Containerized CI Pipeline (SBOM + Policy Gate)

A DevOps mini-project demonstrating **software supply chain security** for a
containerized application: every image built by CI is scanned for
vulnerabilities, accompanied by a signed Software Bill of Materials (SBOM),
cryptographically signed, and only allowed to "deploy" if it passes an
OPA/Conftest policy gate.

## Why this matters

Attacks like **SolarWinds (2020)** and the **Codecov bash uploader
compromise** succeeded by tampering with software during build/distribution
rather than exploiting the running application. Two enterprise responses to
that class of attack are:

1. **Know what's inside your artifact** — an SBOM lists every package/library
   in the image, so a newly disclosed CVE (e.g. Log4Shell) can be matched
   against your fleet in minutes instead of days.
2. **Prove where the artifact came from** — signing the image (and the SBOM
   itself) means a consumer can cryptographically verify it was built by your
   CI, from your source, and hasn't been tampered with in the registry.

This project wires both into an automated **policy gate**: a deployment is
blocked unless the image is signed *and* free of critical vulnerabilities —
enforced as code (Rego), not a manual checklist.

## Architecture

```
 push to main / PR
      │
      ▼
┌─────────────────────────────┐
│ policy-unit-tests (CI job)  │
│  conftest verify -p policy  │──> verifies deny_test.rego (Shift-Left)
└──────────────┬───────────────┘
               ▼ (only if policy tests pass)
┌─────────────────────────────┐
│ build-scan-sign (CI job)    │
│  1. docker build            │
│  2. push to GHCR            │
│  3. Trivy vulnerability scan│──> trivy-report.json, trivy-results.sarif
│  4. Syft SBOM (CycloneDX)   │──> sbom.json
│  5. Cosign sign (keyless)   │──> signature in Rekor transparency log
│  6. Cosign attest SBOM      │──> signed SBOM attestation on the image
│  7. Cosign verify           │──> signed: true/false
│  8. build facts.json        │──> {signed, critical_count, high_count, ...}
└──────────────┬───────────────┘
               ▼
┌─────────────────────────────┐
│ policy-gate (CI job)        │
│  conftest test facts.json   │──> ALLOW or DENY (Rego policy)
│  -p policy/deny.rego        │
│  generate-summary.py        │──> PR security comment & run dashboard
└──────────────┬───────────────┘
               ▼ (only if allowed)
┌─────────────────────────────┐
│ deploy (CI job, simulated)  │
└─────────────────────────────┘
```

## Stack

| Concern              | Tool                                         |
|----------------------|-----------------------------------------------|
| App                  | Python Flask (`app/`)                        |
| Container            | Docker, non-root user, healthcheck           |
| Registry             | GitHub Container Registry (`ghcr.io`)        |
| Vulnerability scan   | [Trivy](https://github.com/aquasecurity/trivy) |
| SBOM generation      | [Syft](https://github.com/anchore/syft)      |
| Image signing        | [Cosign](https://github.com/sigstore/cosign) — **keyless**, via Sigstore + GitHub OIDC |
| Policy gate & tests  | [OPA](https://www.openpolicyagent.org/) via [Conftest](https://www.conftest.dev/) |
| CI                   | GitHub Actions                               |

### Why keyless signing?

Instead of generating a private key and storing it as a GitHub secret (which
can leak, expire, or be exfiltrated), Cosign's keyless mode issues a
**short-lived certificate** bound to the GitHub Actions OIDC identity of the
exact workflow run that built the image. Every signature is recorded in the
public **Rekor transparency log**, so anyone can verify *which workflow, in
which repo, on which commit* produced a signature — without any team ever
handling a long-lived private key.

### Why automated policy unit tests?

Security policies are mission-critical code. Before deploying or building
images, `policy/deny_test.rego` formally tests `policy/deny.rego` across
positive and negative cases (unsigned rejection, critical CVE threshold,
high/medium non-blocking allowances) in milliseconds.

## Repository layout

```
app/
  app.py              Flask app (/ and /health)
  requirements.txt
  Dockerfile
policy/
  deny.rego           Conftest policy: deny if unsigned or critical CVEs > 0
  deny_test.rego      Automated unit test suite verifying policy logic edge cases
scripts/
  build-facts.py      Trivy JSON + signed flag -> facts.json
  generate-summary.py Generates markdown security report for PR comments and summaries
  local-pipeline.sh   Run build/scan/SBOM/gate locally on macOS / Linux (Bash)
  local-pipeline.ps1  Run build/scan/SBOM/gate locally on Windows (PowerShell)
.github/workflows/
  pipeline.yml        policy-unit-tests -> build-scan-sign -> policy-gate -> deploy
```

## Running it

### In CI (GitHub Actions)

Push to `main` (or open a PR against it). The workflow:

1. Builds and pushes the image to `ghcr.io/<owner>/<repo>`
2. Scans it with Trivy (results also appear under the repo's **Security ▸
   Code scanning** tab)
3. Generates a CycloneDX SBOM with Syft
4. Signs the image and attests the SBOM with Cosign (keyless)
5. Runs the Conftest policy gate against the scan + signature results
6. Runs the (simulated) deploy job — only if the gate passes

Check the run in the **Actions** tab. Pipeline artifacts (`facts.json`,
`sbom.json`, `trivy-report.json`, `trivy-results.sarif`,
`cosign-verify.json`) are uploaded to the run for inspection.

### In Pull Requests (Interactive Security Summary)

When a Pull Request is opened or updated, CI runs all security stages and automatically publishes or updates a sticky comment directly on the PR with:
- 🚦 **Policy Gate Decision**: 🟢 **PASSED** or 🔴 **BLOCKED** with clear violation diagnostics.
- ✍️ **Cosign Signature Status**: Verification status via Sigstore OIDC & Rekor transparency log.
- 🛡️ **Vulnerability Breakdown**: Critical, High, Medium, Low counts + detailed table of findings.
- 📋 **SBOM Inventory**: Direct vs. transitive application packages & base OS packages.

### Locally on macOS / Linux (Bash)

Requires Docker Desktop and Python 3.

```bash
# Make script executable (first time only)
chmod +x scripts/local-pipeline.sh

# Run pipeline (simulating a signed, compliant image -> gate PASSES)
./scripts/local-pipeline.sh

# Run ONLY the automated Rego policy unit tests
./scripts/local-pipeline.sh --test-only

# Demo a policy violation (simulating an unsigned image -> gate FAILS)
./scripts/local-pipeline.sh --unsigned
```

### Locally on Windows (PowerShell)

Requires Docker Desktop and Python 3.

```powershell
# Simulate a signed, scanned image -> gate should PASS
./scripts/local-pipeline.ps1 -Signed:$true

# Simulate an unsigned image -> gate should FAIL
./scripts/local-pipeline.ps1 -Signed:$false
```

### Demonstrating a policy failure (for the viva)

Two easy ways to show the gate actually blocking something:

- **Unsigned image**: run `./scripts/local-pipeline.sh --unsigned` (or Windows: `./scripts/local-pipeline.ps1 -Signed:$false`) and show Conftest's DENY output.
- **Critical CVE**: temporarily point `app/Dockerfile`'s base image at an old tag known to have CRITICAL CVEs (e.g. `python:3.9-slim` or older), rerun the pipeline, and show Trivy's findings flow through to a DENY.

### Verifying a signed image from outside CI

Anyone can independently verify the signature and SBOM attestation on a
published image without any special access:

```bash
cosign verify \
  --certificate-identity-regexp "^https://github.com/<owner>/<repo>/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/<owner>/<repo>@<digest>

cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/<owner>/<repo>/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/<owner>/<repo>@<digest>
```

## Viva talking points

- **Supply chain, not just application security**: the target isn't a bug in
  the Flask app, it's trust in the *build and distribution* process — the
  same class of risk as SolarWinds.
- **SBOM as inventory**: when the next Log4Shell-style CVE drops, an SBOM
  lets you grep every image you've shipped for the affected package instead
  of re-scanning everything from scratch.
- **Keyless signing removes a whole class of secret-management risk** — no
  private key to rotate, store, or leak.
- **Policy-as-code gate**: the same Rego policy could gate a real `kubectl
  apply` or Helm release; today it gates a simulated deploy job, but the
  enforcement point is identical to production practice.
- **Transparency log (Rekor)**: even if attackers compromised the registry,
  they can't forge a valid signature for a different artifact without it
  showing up as a public, auditable record.
