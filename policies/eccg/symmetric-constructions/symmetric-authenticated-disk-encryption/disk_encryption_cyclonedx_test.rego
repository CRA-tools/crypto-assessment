package cbom.eccg.section_tests.disk_encryption

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_constructions.disk_encryption.findings

# Disk-encryption findings (ECCG-DISK-001 through ECCG-DISK-004). XTS and CBC-ESSIV
# receive operational warnings. Other encryption components can receive low-severity
# findings because disk-use context is not reliably available.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("XTS with cipher suffix", [test_helpers.algorithm("XTS-AES-256", "block-cipher", {})], [{"ruleId": "ECCG-DISK-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("custom XTS composite", [test_helpers.algorithm("AES-XTS-custom", "block-cipher", {})], [{"ruleId": "ECCG-DISK-001", "severity": "low", "bomRef": "algorithm-under-test"}]),
	# An agreed construction still needs review of tweak or sector-number handling.
	test_helpers.case("XTS tweak notes", [test_helpers.algorithm("AES-XTS", "block-cipher", {})], [{"ruleId": "ECCG-DISK-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("CBC ESSIV sector notes", [test_helpers.algorithm("AES-CBC-ESSIV", "block-cipher", {})], [{"ruleId": "ECCG-DISK-004", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# These low-severity findings reflect uncertain disk-encryption context; the fixtures
	# do not assert that the algorithm is actually used on a disk.
	test_helpers.case("general GCM has heuristic disk warning", [test_helpers.algorithm("AES-GCM", "ae", {"mode": "gcm"})], [{"ruleId": "ECCG-DISK-001", "severity": "low", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("stream cipher disk warnings", [test_helpers.algorithm("ChaCha20", "stream-cipher", {})], [{"ruleId": "ECCG-DISK-001", "severity": "low", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-DISK-002", "severity": "low", "bomRef": "algorithm-under-test"}]),
	# A plain CBC name supplies no ESSIV-composition evidence in this fixture.
	test_helpers.case("CBC name alone is not ESSIV", [test_helpers.algorithm("AES-CBC", "block-cipher", {})], [{"ruleId": "ECCG-DISK-001", "severity": "low", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("AES-XTS", "mac", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("AES-XTS", "block-cipher", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-DISK-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.section == "Symmetric Constructions"
		finding.subsection == "Disk Encryption"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Constructions / Disk Encryption"
	}
}
