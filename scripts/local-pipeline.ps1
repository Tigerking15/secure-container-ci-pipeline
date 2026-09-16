<#
.SYNOPSIS
    Runs the secure container CI pipeline locally on Windows for demo/testing
    purposes, using Docker to run Trivy, Syft and Conftest without installing
    them natively.

.DESCRIPTION
    Mirrors the GitHub Actions workflow (.github/workflows/pipeline.yml):
      1. Build the Docker image
      2. Scan it with Trivy -> trivy-report.json
      3. Generate an SBOM with Syft -> sbom.json
      4. Build facts.json (severity counts + signed flag)
      5. Evaluate policy/deny.rego with Conftest

    Real Cosign signing needs a pushed registry image (that's what the CI
    keyless-signing job does). For local runs, use -Signed:$false to
    demonstrate the policy gate blocking an unsigned image, or -Signed:$true
    (default) to simulate a signed image.

.PARAMETER ImageName
    Local tag to build, e.g. secure-container-ci-pipeline:local

.PARAMETER Signed
    Simulated signature status fed into facts.json ($true/$false).

.EXAMPLE
    ./scripts/local-pipeline.ps1
    ./scripts/local-pipeline.ps1 -Signed:$false   # demo a gate failure
#>

param(
    [string]$ImageName = "secure-container-ci-pipeline:local",
    [bool]$Signed = $true
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

Step "Building Docker image ($ImageName)"
docker build -t $ImageName ./app
if ($LASTEXITCODE -ne 0) { throw "docker build failed" }

Step "Scanning image with Trivy"
docker run --rm `
    -v /var/run/docker.sock:/var/run/docker.sock `
    -v "${root}:/output" `
    aquasec/trivy image --format json --output /output/trivy-report.json $ImageName
if ($LASTEXITCODE -ne 0) { throw "trivy scan failed" }

Step "Generating SBOM with Syft"
docker run --rm `
    -v /var/run/docker.sock:/var/run/docker.sock `
    -v "${root}:/output" `
    anchore/syft $ImageName -o cyclonedx-json=/output/sbom.json
if ($LASTEXITCODE -ne 0) { throw "syft SBOM generation failed" }

Step "Building facts.json (signed=$Signed)"
python scripts/build-facts.py --trivy-report trivy-report.json --signed $Signed --out facts.json
if ($LASTEXITCODE -ne 0) { throw "build-facts.py failed" }
Get-Content facts.json

Step "Evaluating OPA/Conftest policy gate"
docker run --rm -v "${root}:/project" -w /project openpolicyagent/conftest test facts.json -p policy/deny.rego
$gateExitCode = $LASTEXITCODE

Write-Host ""
if ($gateExitCode -eq 0) {
    Write-Host "POLICY GATE: PASSED - image would be allowed to deploy." -ForegroundColor Green
} else {
    Write-Host "POLICY GATE: FAILED - deployment would be blocked." -ForegroundColor Red
}
exit $gateExitCode
