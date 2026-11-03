package cbom.eccg.section_tests.drbg

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.findings

# DRBG findings (ECCG-DRBG-001 through ECCG-DRBG-005). HMAC_DRBG, Hash_DRBG, and
# CTR_DRBG are agreed; the seed, quantum-resistance, backtracking, and CTR-specific
# notes remain advisory.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("DRBG wrapper is not the generator", [test_helpers.algorithm("HMAC_DRBG-SHA256-wrapper", "drbg", {})], [{"ruleId": "ECCG-DRBG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC DRBG", [test_helpers.algorithm("HMAC_DRBG", "drbg", {})], [{"ruleId": "ECCG-DRBG-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-004", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("Hash DRBG", [test_helpers.algorithm("Hash_DRBG-SHA256", "drbg", {})], [{"ruleId": "ECCG-DRBG-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-004", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# CTR_DRBG receives the three general warnings and the additional block-cipher key-size
	# advisory.
	test_helpers.case("CTR DRBG", [test_helpers.algorithm("CTR_DRBG-AES-128", "drbg", {})], [{"ruleId": "ECCG-DRBG-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-005", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# A generic parameterSetIdentifier cannot prove seed entropy or the key size of an
	# internal block cipher, so it does not remove the warning.
	test_helpers.case("CTR parameter size cannot prove underlying key length", [test_helpers.algorithm("CTR_DRBG", "drbg", {"parameterSetIdentifier": "256"})], [{"ruleId": "ECCG-DRBG-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-005", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unagreed Dual EC DRBG", [test_helpers.algorithm("Dual_EC_DRBG", "drbg", {})], [{"ruleId": "ECCG-DRBG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unagreed Fortuna", [test_helpers.algorithm("Fortuna", "drbg", {"algorithmFamily": "Fortuna"})], [{"ruleId": "ECCG-DRBG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("registry family overrides name", [test_helpers.algorithm("HMAC_DRBG", "drbg", {"algorithmFamily": "Fortuna"})], [{"ruleId": "ECCG-DRBG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("recognized family", [test_helpers.algorithm("opaque", "drbg", {"algorithmFamily": "HMAC_DRBG"})], [{"ruleId": "ECCG-DRBG-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-004", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# A hash OID identifies a building block, not a DRBG construction.
	test_helpers.case("building block OID is insufficient", [test_helpers.with_oid(test_helpers.algorithm("opaque", "drbg", {}), "2.16.840.1.101.3.4.2.1")], [{"ruleId": "ECCG-DRBG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unknown OID permits name fallback", [test_helpers.with_oid(test_helpers.algorithm("Hash_DRBG", "drbg", {}), "1.2.3.4.5")], [{"ruleId": "ECCG-DRBG-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-004", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("HMAC_DRBG", "mac", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("HMAC_DRBG", "drbg", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-DRBG-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DRBG-004", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.section == "Random Number Generation"
		finding.subsection == "Deterministic Random Bit Generator"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Random Number Generation / Deterministic Random Bit Generator"
	}
}
