package main

import rego.v1

# Policy gate for the secure containerized CI pipeline.
#
# Expects input shaped like:
# {
#   "signed": true,
#   "critical_count": 0,
#   "high_count": 3
# }
#
# The image must be cryptographically signed (Cosign) AND must have zero
# CRITICAL severity CVEs (Trivy) to pass the gate. HIGH severity CVEs are
# reported but do not block, so the count is only informational here.

deny contains msg if {
    input.signed == false
    msg := "policy violation: container image is not signed with Cosign"
}

deny contains msg if {
    input.critical_count > 0
    msg := sprintf("policy violation: image has %d CRITICAL severity CVE(s)", [input.critical_count])
}
