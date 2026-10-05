package main

import rego.v1

# Unit tests for policy/deny.rego
# Run with: conftest verify -p policy

# 1. Reject unsigned images
test_deny_unsigned_image if {
	result := deny with input as {
		"signed": false,
		"critical_count": 0,
		"high_count": 0,
	}
	result == {"policy violation: container image is not signed with Cosign"}
}

# 2. Reject images with single critical CVE
test_deny_single_critical_cve if {
	result := deny with input as {
		"signed": true,
		"critical_count": 1,
		"high_count": 0,
	}
	result == {"policy violation: image has 1 CRITICAL severity CVE(s)"}
}

# 3. Reject images with multiple critical CVEs
test_deny_multiple_critical_cves if {
	result := deny with input as {
		"signed": true,
		"critical_count": 3,
		"high_count": 4,
	}
	result == {"policy violation: image has 3 CRITICAL severity CVE(s)"}
}

# 4. Reject when both unsigned AND has critical CVEs (multiple violations)
test_deny_unsigned_and_critical if {
	result := deny with input as {
		"signed": false,
		"critical_count": 2,
		"high_count": 1,
	}
	result == {
		"policy violation: container image is not signed with Cosign",
		"policy violation: image has 2 CRITICAL severity CVE(s)",
	}
}

# 5. Allow compliant image (signed + 0 critical CVEs)
test_allow_clean_signed_image if {
	count(deny) == 0 with input as {
		"signed": true,
		"critical_count": 0,
		"high_count": 0,
	}
}

# 6. Allow image with non-critical CVEs (High / Medium / Low do not block)
test_allow_high_and_medium_cves if {
	count(deny) == 0 with input as {
		"signed": true,
		"critical_count": 0,
		"high_count": 8,
		"medium_count": 12,
		"low_count": 25,
	}
}
