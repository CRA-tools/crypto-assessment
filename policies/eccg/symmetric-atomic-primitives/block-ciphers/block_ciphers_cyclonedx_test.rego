package cbom.eccg.section_tests.block_ciphers

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.block_ciphers.findings

# Block-cipher findings (ECCG-BLOCK-001 through ECCG-BLOCK-005). These cases separate
# AES key-size agreement from the 192-bit quantum advisory, and check both 3DES key size
# and the end of its legacy period.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	# An agreed AES size can still require a quantum-security advisory. AES-192 and AES-256
	# produce no findings in this section.
	test_helpers.case("AES 128 bits", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "128"})], [{"ruleId": "ECCG-BLOCK-005", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES 192 bits", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "192"})], []),
	test_helpers.case("AES 256 bits", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "256"})], []),
	# Exercise disallowed sizes and missing information. A size above the quantum threshold
	# can still fail AES key-size agreement.
	test_helpers.case("AES invalid size '127'", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "127"})], [{"ruleId": "ECCG-BLOCK-002", "severity": "high", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-005", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES invalid size '129'", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "129"})], [{"ruleId": "ECCG-BLOCK-002", "severity": "high", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-005", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES invalid size '191'", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "191"})], [{"ruleId": "ECCG-BLOCK-002", "severity": "high", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-005", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES invalid size '257'", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "257"})], [{"ruleId": "ECCG-BLOCK-002", "severity": "high", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES invalid size ''", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": ""})], [{"ruleId": "ECCG-BLOCK-002", "severity": "high", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-005", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES invalid size 'unknown'", [test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "unknown"})], [{"ruleId": "ECCG-BLOCK-002", "severity": "high", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-005", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES missing size", [test_helpers.algorithm("AES", "block-cipher", {})], [{"ruleId": "ECCG-BLOCK-002", "severity": "high", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-005", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	# Use an opaque component name to verify recognition from the registered OID or
	# algorithm family alone.
	test_helpers.case("AES known OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "block-cipher", {"parameterSetIdentifier": "256"}), "2.16.840.1.101.3.4.1.42")], []),
	test_helpers.case("AES registry family", [test_helpers.algorithm("opaque", "block-cipher", {"algorithmFamily": "AES", "parameterSetIdentifier": "256"})], []),
	test_helpers.case("unagreed Blowfish", [test_helpers.algorithm("Blowfish", "block-cipher", {"parameterSetIdentifier": "256"})], [{"ruleId": "ECCG-BLOCK-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# Freeze evaluation on either side of the 2027 cutoff. The legacy-rule severity changes
	# to error; the separate non-agreed-cipher finding remains critical.
	object.union(test_helpers.case("3DES legacy final day", [test_helpers.algorithm("3DES", "block-cipher", {"parameterSetIdentifier": "168"})], [{"ruleId": "ECCG-BLOCK-001", "severity": "critical", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-003", "severity": "critical", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2027-12-31T23:59:59Z")}),
	object.union(test_helpers.case("3DES expired legacy", [test_helpers.algorithm("3DES", "block-cipher", {"parameterSetIdentifier": "168"})], [{"ruleId": "ECCG-BLOCK-001", "severity": "critical", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-003", "severity": "error", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2028-01-01T00:00:00Z")}),
	test_helpers.case("3DES wrong size", [test_helpers.algorithm("3DES", "block-cipher", {"parameterSetIdentifier": "112"})], [{"ruleId": "ECCG-BLOCK-001", "severity": "critical", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-003", "severity": "critical", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-BLOCK-004", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("non block cipher", [test_helpers.algorithm("AES", "signature", {"parameterSetIdentifier": "128"})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("AES", "block-cipher", {"parameterSetIdentifier": "128"}), "src/crypto.py", 42)], [{"ruleId": "ECCG-BLOCK-005", "severity": "medium", "bomRef": "algorithm-under-test"}]),
]

# Evaluate each named CBOM against this section alone with a fixed clock. The expected
# finding count, fields, component identity, and source evidence must all match. OPA
# includes test_case.name in failures to identify the input.
test_cyclonedx_cases[test_case.name] if {
	some test_case in cases
	actual_findings := findings with input as test_case.input with time.now_ns as test_case.evaluationTime
	test_helpers.matches(test_case, actual_findings)
}

# Apply the shared empty-BOM, library, protocol, and secret-material cases. None should
# produce findings from this section.
test_cyclonedx_scope[test_case.name] if {
	some test_case in test_helpers.scope_cases
	actual_findings := findings with input as test_case.input with time.now_ns as test_case.evaluationTime
	test_helpers.matches(test_case, actual_findings)
}

# Run the full assessment and select this section’s findings. Other sections can
# legitimately assess the same component; this selection verifies that aggregation
# preserves these findings and their UI location metadata.
test_cyclonedx_main_findings[test_case.name] if {
	some test_case in array.concat(cases, test_helpers.scope_cases)
	all_findings := data.cbom.eccg.findings with input as test_case.input with time.now_ns as test_case.evaluationTime
	section_findings := [finding |
		some finding in all_findings
		finding.section == "Symmetric Atomic Primitives"
		finding.subsection == "Block Ciphers"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Atomic Primitives / Block Ciphers"
	}
}
