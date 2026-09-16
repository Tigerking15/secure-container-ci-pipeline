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
 push to main
      │
      ▼
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
| Policy gate          | [OPA](https://www.openpolicyagent.org/) via [Conftest](https://www.conftest.dev/) |
| CI                   | GitHub Actions                               |

### Why keyless signing?

Instead of generating a private key and storing it as a GitHub secret (which
can leak, expire, or be exfiltrated), Cosign's keyless mode issues a
**short-lived certificate** bound to the GitHub Actions OIDC identity of the
exact workflow run that built the image. Every signature is recorded in the
public **Rekor transparency log**, so anyone can verify *which workflow, in
which repo, on which commit* produced a signature — without any team ever
handling a long-lived private key.

### Why a Rego policy instead of `if` statements in YAML?

The gate logic (`policy/deny.rego`) is decoupled from the pipeline plumbing.
It can be unit-tested, versioned, and reused across pipelines, and it's easy
to demo live: change one line in the policy or in `facts.json` and re-run
`conftest` to show the gate flip from ALLOW to DENY.

## Repository layout

```
app/
  app.py              Flask app (/ and /health)
  requirements.txt
  Dockerfile
policy/
  deny.rego           Conftest policy: deny if unsigned or critical CVEs > 0
scripts/
  build-facts.py      Trivy JSON + signed flag -> facts.json
  local-pipeline.ps1  Run build/scan/SBOM/gate locally on Windows
.github/workflows/
  pipeline.yml        build-scan-sign -> policy-gate -> deploy
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

### Locally (Windows / PowerShell)

Requires Docker Desktop and Python 3.

```powershell
./scripts/local-pipeline.ps1
```

This builds the image, runs Trivy and Syft via their official Docker images
(no local install needed), builds `facts.json`, and evaluates the policy
with Conftest. Real Cosign signing requires a pushed registry image (that's
what the CI job does) — locally, the script takes a `-Signed` flag to
simulate the signature check:

```powershell
# Simulate a signed, scanned image -> gate should PASS
./scripts/local-pipeline.ps1 -Signed:$true

# Simulate an unsigned image -> gate should FAIL
./scripts/local-pipeline.ps1 -Signed:$false
```

### Demonstrating a policy failure (for the viva)

Two easy ways to show the gate actually blocking something:

- **Unsigned image**: run `./scripts/local-pipeline.ps1 -Signed:$false` and
  show Conftest's DENY output.
- **Critical CVE**: temporarily point `app/Dockerfile`'s base image at an old
  tag known to have CRITICAL CVEs (e.g. `python:3.9-slim` or older), rerun
  the pipeline, and show Trivy's findings flow through to a DENY.

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
