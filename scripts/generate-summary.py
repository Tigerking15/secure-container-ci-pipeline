#!/usr/bin/env python3
"""Generate a Markdown Security Summary report from facts.json, sbom.json,
Trivy scan results, and Conftest policy evaluation.

Used both for GitHub Actions $GITHUB_STEP_SUMMARY / Pull Request comments
and local pipeline runs.
"""
import argparse
import json
import os
import re
import sys


def load_direct_requirements(req_path):
    direct = set()
    if not req_path or not os.path.exists(req_path):
        return direct
    try:
        with open(req_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line = line.split("#")[0].strip()
                name = re.split(r"[=<>]", line)[0].strip().lower()
                if name:
                    direct.add(name)
    except Exception:
        pass
    return direct


def parse_sbom(sbom_path, direct_reqs):
    if not sbom_path or not os.path.exists(sbom_path):
        return None
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    components = data.get("components") or []
    direct_packages = []
    transitive_python = []
    os_packages = []
    other_packages = []

    for comp in components:
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        properties = comp.get("properties") or []
        
        is_python = (
            "pkg:pypi/" in purl
            or any(p.get("name") == "syft:language" and p.get("value") == "python" for p in properties)
        )
        
        display_str = f"`{name}@{version}`" if version else f"`{name}`"

        if is_python:
            if name.lower() in direct_reqs:
                direct_packages.append(display_str)
            else:
                transitive_python.append(display_str)
        elif any(pkg_mgr in purl for pkg_mgr in ("pkg:deb/", "pkg:apk/", "pkg:rpm/", "pkg:alpm/")):
            os_packages.append(display_str)
        else:
            other_packages.append(display_str)

    return {
        "total": len(components),
        "direct_python": sorted(direct_packages),
        "transitive_python": sorted(transitive_python),
        "os_count": len(os_packages),
        "other_count": len(other_packages),
    }


def parse_trivy_vulns(trivy_path):
    if not trivy_path or not os.path.exists(trivy_path):
        return []
    vulns = []
    try:
        with open(trivy_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        for res in report.get("Results") or []:
            target = res.get("Target", "")
            for v in res.get("Vulnerabilities") or []:
                vulns.append({
                    "id": v.get("VulnerabilityID", "N/A"),
                    "pkg": v.get("PkgName", "N/A"),
                    "installed": v.get("InstalledVersion", "N/A"),
                    "fixed": v.get("FixedVersion", "None"),
                    "severity": v.get("Severity", "UNKNOWN").upper(),
                    "title": v.get("Title") or v.get("Description") or "",
                    "target": target,
                })
    except Exception:
        pass
    return vulns


def parse_conftest_violations(conftest_output_path, facts):
    violations = []
    if conftest_output_path and os.path.exists(conftest_output_path):
        try:
            with open(conftest_output_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "policy violation:" in line:
                        # Extract the message starting from policy violation
                        idx = line.find("policy violation:")
                        violations.append(line[idx:])
                    elif line.startswith("FAIL -"):
                        violations.append(line)
        except Exception:
            pass

    # Fallback to computing from facts if output file didn't have violations parsed
    if not violations and facts:
        if not facts.get("signed", False):
            violations.append("policy violation: container image is not signed with Cosign")
        crit = facts.get("critical_count", 0)
        if crit > 0:
            violations.append(f"policy violation: image has {crit} CRITICAL severity CVE(s)")

    return violations


def build_markdown_summary(facts, sbom_info, vulns, violations, image_ref=None):
    is_signed = facts.get("signed", False)
    crit_count = facts.get("critical_count", 0)
    high_count = facts.get("high_count", 0)
    med_count = facts.get("medium_count", 0)
    low_count = facts.get("low_count", 0)

    is_passed = len(violations) == 0 and is_signed and crit_count == 0

    lines = []
    lines.append("## 🛡️ Container Supply Chain Security Report")
    lines.append("")

    if image_ref:
        lines.append(f"**Target Artifact**: `{image_ref}`")
        lines.append("")

    # 1. Gate Verdict
    if is_passed:
        lines.append("### 🚦 Gate Verdict: 🟢 **PASSED (Allowed to Deploy)**")
        lines.append("> ✅ **Policy Approval**: Container image is cryptographically verified and meets all security criteria (zero CRITICAL CVEs).")
    else:
        lines.append("### 🚦 Gate Verdict: 🔴 **BLOCKED (Deployment Denied)**")
        lines.append("> ❌ **Policy Violations**: Deployment is halted due to the following policy failures:")
        for v in violations:
            lines.append(f"> - ⚠️ **{v}**")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 2. Cosign Verification Status
    lines.append("### ✍️ Cryptographic Provenance (Cosign)")
    lines.append("| Verification Check | Status | Details |")
    lines.append("| :--- | :---: | :--- |")
    if is_signed:
        lines.append("| **Image Signature** | 🟢 **VERIFIED** | Keyless Sigstore certificate validated against GitHub OIDC identity & Rekor log |")
        lines.append("| **SBOM Attestation** | 🟢 **ATTACHED** | CycloneDX in-toto attestation signed and cryptographically bound to digest |")
    else:
        lines.append("| **Image Signature** | 🔴 **NOT SIGNED** | Missing or invalid cryptographic signature |")
        lines.append("| **SBOM Attestation** | ⚪ **UNVERIFIED** | No verifiable attestation attached to image digest |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 3. Trivy Vulnerability Breakdown
    lines.append("### 🛡️ Vulnerability Analysis (Trivy)")
    lines.append("| Severity | Detected | Policy Limit | Status |")
    lines.append("| :--- | :---: | :---: | :---: |")
    crit_status = "✅ Satisfied" if crit_count == 0 else "❌ **Violated** (Blocks Deploy)"
    lines.append(f"| 🚨 **CRITICAL** | **{crit_count}** | 0 | {crit_status} |")
    lines.append(f"| 🟠 **HIGH** | **{high_count}** | Warn | ℹ️ Monitored |")
    lines.append(f"| 🟡 **MEDIUM** | **{med_count}** | Allow | ℹ️ Monitored |")
    lines.append(f"| ⚪ **LOW** | **{low_count}** | Allow | ℹ️ Monitored |")
    lines.append("")

    # Vulnerability details table (if any)
    crit_and_high = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
    if crit_and_high:
        lines.append("<details>")
        lines.append(f"<summary>🔍 <b>View {len(crit_and_high)} Critical & High Severity Finding(s)</b></summary>")
        lines.append("")
        lines.append("| CVE ID | Severity | Package | Installed Version | Fixed Version | Title |")
        lines.append("| :--- | :---: | :--- | :--- | :--- | :--- |")
        for v in crit_and_high[:15]:
            title = (v["title"][:50] + "...") if len(v["title"]) > 50 else v["title"]
            lines.append(f"| `{v['id']}` | **{v['severity']}** | `{v['pkg']}` | `{v['installed']}` | `{v['fixed']}` | {title} |")
        if len(crit_and_high) > 15:
            lines.append(f"\n*...and {len(crit_and_high) - 15} more findings omitted for brevity.*")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    elif crit_count == 0 and high_count == 0:
        lines.append("🎉 *Zero Critical or High severity vulnerabilities detected in application and base layers.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    # 4. SBOM Inventory Summary
    lines.append("### 📋 SBOM Dependency Inventory (Syft / CycloneDX)")
    if sbom_info:
        lines.append(f"- **Total Components Cataloged**: **{sbom_info['total']}**")
        lines.append(f"- **Direct Application Dependencies ({len(sbom_info['direct_python'])})**: " +
                     (", ".join(sbom_info['direct_python']) if sbom_info['direct_python'] else "*None*"))
        lines.append(f"- **Transitive Python Dependencies ({len(sbom_info['transitive_python'])})**: " +
                     (", ".join(sbom_info['transitive_python']) if sbom_info['transitive_python'] else "*None*"))
        lines.append(f"- **Base OS Packages (Debian)**: **{sbom_info['os_count']}** packages")
        if sbom_info['other_count'] > 0:
            lines.append(f"- **Other Components**: **{sbom_info['other_count']}**")
    else:
        lines.append("*(SBOM data not available or not evaluated)*")
    lines.append("")

    lines.append("---")
    lines.append("*Report generated automatically by Secure Container CI Pipeline Gate.*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate Supply Chain Security Markdown Report")
    parser.add_argument("--facts", required=True, help="Path to facts.json")
    parser.add_argument("--sbom", default=None, help="Path to sbom.json")
    parser.add_argument("--trivy-report", default=None, help="Path to trivy-report.json")
    parser.add_argument("--conftest-output", default=None, help="Path to conftest-output.txt")
    parser.add_argument("--requirements", default="app/requirements.txt", help="Path to requirements.txt")
    parser.add_argument("--image-ref", default=None, help="Docker image reference name/digest")
    parser.add_argument("--out", default="summary.md", help="Output Markdown report path")
    args = parser.parse_args()

    # Load facts
    try:
        with open(args.facts, "r", encoding="utf-8") as f:
            facts = json.load(f)
    except Exception as e:
        print(f"Error loading facts from {args.facts}: {e}", file=sys.stderr)
        sys.exit(1)

    direct_reqs = load_direct_requirements(args.requirements)
    sbom_info = parse_sbom(args.sbom, direct_reqs)
    vulns = parse_trivy_vulns(args.trivy_report)
    violations = parse_conftest_violations(args.conftest_output, facts)

    markdown = build_markdown_summary(facts, sbom_info, vulns, violations, args.image_ref)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(markdown)

    print(f"Successfully generated security summary at {args.out}")


if __name__ == "__main__":
    main()
