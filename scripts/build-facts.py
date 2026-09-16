#!/usr/bin/env python3
"""Build facts.json for the Conftest policy gate from a Trivy JSON report
and a signature-verification result.

Usage:
    python build-facts.py --trivy-report trivy-report.json --signed true --out facts.json
"""
import argparse
import json
import sys


def count_severities(trivy_report):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for result in trivy_report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def str_to_bool(value):
    return value.strip().lower() in ("1", "true", "yes", "y")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy-report", required=True, help="Path to Trivy JSON report")
    parser.add_argument("--signed", required=True, help="true/false whether cosign verify succeeded")
    parser.add_argument("--out", default="facts.json", help="Output path for facts.json")
    args = parser.parse_args()

    try:
        with open(args.trivy_report, "r", encoding="utf-8") as f:
            trivy_report = json.load(f)
    except FileNotFoundError:
        print(f"error: trivy report not found at {args.trivy_report}", file=sys.stderr)
        sys.exit(1)

    counts = count_severities(trivy_report)

    facts = {
        "signed": str_to_bool(args.signed),
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(facts, f, indent=2)

    print(f"wrote {args.out}: {json.dumps(facts)}")


if __name__ == "__main__":
    main()
