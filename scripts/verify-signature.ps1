<#
.SYNOPSIS
    Verifies the Cosign (keyless) signature of the published image and prints a readable summary.

.PARAMETER Digest
    Image digest (sha256:...) copied from the "Build and push image" step of a green Actions run.

.EXAMPLE
    ./scripts/verify-signature.ps1 -Digest sha256:521b8b019c2d3649e9fa62e4a299581a2eeb17a0feddf060475a146409062d0b
#>
param(
    [string]$Digest = 'sha256:521b8b019c2d3649e9fa62e4a299581a2eeb17a0feddf060475a146409062d0b',
    [string]$Repo = 'Tigerking15/secure-container-ci-pipeline'
)

$image = "ghcr.io/$($Repo.ToLower())@$Digest"
Write-Host ""
Write-Host "Verifying signature of:" -ForegroundColor Cyan
Write-Host "  $image"
Write-Host "Running cosign inside Docker (no install needed)..." -ForegroundColor DarkGray

$errFile = New-TemporaryFile
$json = docker run --rm --dns 8.8.8.8 --dns 1.1.1.1 gcr.io/projectsigstore/cosign:v2.4.1 verify `
    --certificate-identity-regexp "^https://github.com/$Repo/" `
    --certificate-oidc-issuer https://token.actions.githubusercontent.com $image 2>$errFile
$code = $LASTEXITCODE
Remove-Item $errFile -ErrorAction SilentlyContinue

if ($code -ne 0) {
    Write-Host "`nSIGNATURE NOT VERIFIED (cosign exit code $code)" -ForegroundColor Red
    exit $code
}

$parsed = ($json -join '') | ConvertFrom-Json
$sig = if ($parsed -is [array]) { $parsed[0] } else { $parsed }
$opt = $sig.optional
$time = [DateTimeOffset]::FromUnixTimeSeconds($opt.Bundle.Payload.integratedTime).LocalDateTime

Write-Host "`n  [OK] Signature is valid and matches this exact image digest" -ForegroundColor Green
Write-Host "  [OK] Entry found in the public Rekor transparency log" -ForegroundColor Green
Write-Host "  [OK] Certificate chains to the Sigstore certificate authority" -ForegroundColor Green

Write-Host "`nWho signed it (taken from the certificate):" -ForegroundColor Cyan
$rows = [ordered]@{
    'Repository'  = $opt.githubWorkflowRepository
    'Workflow'    = ($opt.Subject -replace '^https://github.com/[^/]+/[^/]+/', '')
    'Trigger'     = $opt.githubWorkflowTrigger
    'Branch'      = $opt.githubWorkflowRef
    'Commit'      = $opt.githubWorkflowSha
    'Identity by' = $opt.Issuer
    'Signed at'   = $time
    'Rekor index' = $opt.Bundle.Payload.logIndex
}
$rows.GetEnumerator() | ForEach-Object { Write-Host ('  {0,-12} {1}' -f $_.Key, $_.Value) }

Write-Host "`nResult: this image was built and signed by our GitHub Actions workflow, with no private key involved.`n" -ForegroundColor Green
