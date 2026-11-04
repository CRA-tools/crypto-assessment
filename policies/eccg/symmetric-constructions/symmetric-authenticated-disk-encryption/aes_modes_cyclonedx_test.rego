package cbom.eccg.section_tests.aes_modes

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_constructions.symmetric_encryption_schemes.aes_modes.findings

# Symmetric-encryption findings (ECCG-SYM-ENC-001 through ECCG-SYM-ENC-006). Fixtures
# cover conditional encryption modes, IV requirements, and the additional GCM
# operational advisories.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("CBC with padding and IV length", [test_helpers.algorithm("AES-256-CBC-PKCS7Padding-128", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("CFB64 is a CFB construction", [test_helpers.algorithm("AES-256-CFB64", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("ECB with padding remains forbidden", [test_helpers.algorithm("AES-256-ECB-PKCS7Padding", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("custom CBC composite", [test_helpers.algorithm("AES-CBC-custom", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# Agreed confidentiality modes retain integrity and IV review warnings. These fixtures
	# do not establish how the application generates IVs or provides integrity.
	test_helpers.case("conditional CTR", [test_helpers.algorithm("AES-CTR", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("conditional OFB", [test_helpers.algorithm("AES-OFB", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("conditional CBC", [test_helpers.algorithm("AES-CBC", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("conditional CBC-CS", [test_helpers.algorithm("AES-CBC-CS", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("conditional CFB", [test_helpers.algorithm("AES-CFB", "block-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("ECB is not agreed", [test_helpers.algorithm("AES-ECB", "block-cipher", {"mode": "ecb"})], [{"ruleId": "ECCG-SYM-ENC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# GCM emits separate IV, construction, plaintext-length, and tag-length advisories, so
	# their IDs are asserted individually.
	test_helpers.case("GCM notes", [test_helpers.algorithm("AES-GCM", "ae", {"algorithmFamily": "AES", "mode": "gcm"})], [{"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-005", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-006", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("CCM IV note", [test_helpers.algorithm("AES-CCM", "ae", {"mode": "ccm"})], [{"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("EAX IV note", [test_helpers.algorithm("AES-EAX", "ae", {})], [{"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# Recognized disk-encryption and key-protection constructions must not be rejected by
	# the general symmetric-encryption agreement check.
	test_helpers.case("XTS belongs to disk encryption", [test_helpers.algorithm("AES-XTS", "block-cipher", {})], []),
	test_helpers.case("key wrap belongs to key protection", [test_helpers.algorithm("AES-KW", "ae", {})], []),
	test_helpers.case("unagreed stream cipher", [test_helpers.algorithm("ChaCha20", "stream-cipher", {})], [{"ruleId": "ECCG-SYM-ENC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("known GCM OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "ae", {}), "2.16.840.1.101.3.4.1.6")], [{"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-005", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-006", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("family and mode", [test_helpers.algorithm("opaque", "block-cipher", {"algorithmFamily": "AES", "mode": "cfb"})], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("AES-GCM", "mac", {"mode": "gcm"})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("AES-CTR", "block-cipher", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-SYM-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-SYM-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "AES Modes"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Constructions / AES Modes"
	}
}
