<#
.SYNOPSIS
    Step-by-step demo of the secure container pipeline: success and failure paths.

.PARAMETER Scenario
    tests    Rego policy unit tests only
    pass     Signed image on a modern base (python:3.12-slim)  -> gate PASSES
    unsigned Unsigned image on a modern base                   -> gate BLOCKS (not signed)
    critical Signed image on an old base (python:3.8)          -> gate BLOCKS if CRITICAL CVEs found
    all      Run tests, pass, unsigned, critical in order

.EXAMPLE
    ./scripts/demo.ps1 -Scenario pass
    ./scripts/demo.ps1 -Scenario all -Pause     # press Enter between scenarios while presenting
#>
param(
    [ValidateSet('tests','pass','unsigned','critical','all')][string]$Scenario = 'all',
    [switch]$Pause
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$work = Join-Path $root 'demo-out'
New-Item -ItemType Directory -Force $work | Out-Null

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

function Run-Tests {
    Step 'Policy unit tests (conftest verify)'
    docker run --rm -v "${root}:/project" -w /project openpolicyagent/conftest:v0.56.0 verify -p policy | Out-Host
    return $LASTEXITCODE
}

function Run-Scenario($name, $base, $signed) {
    $tag = "secure-demo:$name"
    $out = Join-Path $work $name
    New-Item -ItemType Directory -Force $out | Out-Null

    Step "[$name] Build image on base $base"
    # Demo-only Dockerfile copy so the repo's real Dockerfile is untouched
    (Get-Content app/Dockerfile) -replace '^FROM .*', "FROM $base" | Set-Content "$out/Dockerfile" -Encoding ascii
    docker build -q -t $tag -f "$out/Dockerfile" ./app | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Host 'build failed' -ForegroundColor Red; return [int]2 }

    Step "[$name] Trivy vulnerability scan"
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${out}:/output" aquasec/trivy image --quiet --format json --output /output/trivy-report.json $tag | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Host 'trivy failed' -ForegroundColor Red; return 2 }

    Step "[$name] Syft SBOM (CycloneDX)"
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${out}:/output" anchore/syft $tag -o cyclonedx-json=/output/sbom.json | Out-Null
    $pkgs = (Get-Content "$out/sbom.json" -Raw | ConvertFrom-Json).components.Count
    Write-Host "SBOM lists $pkgs components"

    Step "[$name] Build facts.json (signed=$signed)"
    # Same logic as scripts/build-facts.py, done in PowerShell so Python is not required
    $rep = Get-Content "$out/trivy-report.json" -Raw | ConvertFrom-Json
    $v = @(); foreach ($r in $rep.Results) { if ($r.Vulnerabilities) { $v += $r.Vulnerabilities } }
    $cnt = { param($s) @($v | Where-Object { $_.Severity -eq $s }).Count }
    $facts = [ordered]@{ signed = $signed; critical_count = (& $cnt 'CRITICAL'); high_count = (& $cnt 'HIGH'); medium_count = (& $cnt 'MEDIUM'); low_count = (& $cnt 'LOW') }
    $facts | ConvertTo-Json | Set-Content "$out/facts.json" -Encoding ascii
    Get-Content "$out/facts.json" | Out-Host

    Step "[$name] OPA/Conftest policy gate"
    docker run --rm -v "${root}:/project" -w /project openpolicyagent/conftest:v0.56.0 test "demo-out/$name/facts.json" -p policy/deny.rego | Out-Host
    $code = $LASTEXITCODE  # captured right after conftest
    if ($code -eq 0) { Write-Host "POLICY GATE: PASSED - deploy allowed" -ForegroundColor Green }
    else             { Write-Host "POLICY GATE: BLOCKED - deploy denied" -ForegroundColor Red }
    return $code
}

$results = [ordered]@{}
function Gate-Pause { if ($Pause) { Read-Host "`nPress Enter for next scenario" | Out-Null } }

if ($Scenario -in 'tests','all') { $results['unit tests (expect 0)'] = Run-Tests; Gate-Pause }
if ($Scenario -in 'pass','all')     { $results['pass (expect 0)']     = Run-Scenario 'pass'     'python:3.12-slim' $true;  Gate-Pause }
if ($Scenario -in 'unsigned','all') { $results['unsigned (expect 1)'] = Run-Scenario 'unsigned' 'python:3.12-slim' $false; Gate-Pause }
if ($Scenario -in 'critical','all') { $results['critical (expect 1)'] = Run-Scenario 'critical' 'python:3.8'        $true }

Step 'Summary (exit codes)'
$results.GetEnumerator() | ForEach-Object { '{0,-24} {1}' -f $_.Key, $_.Value }

