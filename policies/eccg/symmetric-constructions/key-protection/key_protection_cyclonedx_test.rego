package cbom.eccg.section_tests.key_protection

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_constructions.key_protection.findings

# Key-protection findings (ECCG-KP-001). AES-KW, AES-KWP, and SIV are recognized through
# names or assigned OIDs; other eligible constructions receive a medium-severity context
# warning.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("AES KW with trailing key size", [test_helpers.algorithm("AES-KW-256", "key-wrap", {})], []),
	test_helpers.case("AES KWP with trailing key size", [test_helpers.algorithm("AES-KWP-256", "key-wrap", {})], []),
	test_helpers.case("AES KeyWrap with trailing key size", [test_helpers.algorithm("AES-KeyWrap-256", "key-wrap", {})], []),
	test_helpers.case("AES family supplies cipher for KW", [test_helpers.algorithm("KW-256", "key-wrap", {"algorithmFamily": "AES"})], []),
	test_helpers.case("RFC5297 SIV with trailing key size", [test_helpers.algorithm("AES-SIV-256", "ae", {})], []),
	test_helpers.case("AES family alone cannot identify a wrapping construction", [test_helpers.algorithm("opaque", "key-wrap", {"algorithmFamily": "AES"})], [{"ruleId": "ECCG-KP-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("GCM-SIV is not the RFC5297 SIV construction", [test_helpers.algorithm("AES-256-GCM-SIV-128-96", "ae", {})], [{"ruleId": "ECCG-KP-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES Wrap with padding", [test_helpers.algorithm("AES-256-Wrap-PKCS7", "key-wrap", {})], []),
	test_helpers.case("RSA wrapping is not AES key wrap", [test_helpers.algorithm("RSA-KeyWrap", "key-wrap", {})], [{"ruleId": "ECCG-KP-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("custom SIV composite", [test_helpers.algorithm("AES-SIV-custom", "key-wrap", {})], [{"ruleId": "ECCG-KP-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed AES-KW", [test_helpers.algorithm("AES-KW", "key-wrap", {})], []),
	test_helpers.case("agreed AES-KWP", [test_helpers.algorithm("AES-KWP", "key-wrap", {})], []),
	test_helpers.case("agreed AES-KeyWrap", [test_helpers.algorithm("AES-KeyWrap", "key-wrap", {})], []),
	test_helpers.case("agreed AES-SIV", [test_helpers.algorithm("AES-SIV", "key-wrap", {})], []),
	# Exercise ordinary and padded AES key-wrap identifiers without relying on the
	# component name.
	test_helpers.case("key wrap OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "key-wrap", {}), "2.16.840.1.101.3.4.1.5")], []),
	test_helpers.case("padded key wrap OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "key-wrap", {}), "2.16.840.1.101.3.4.1.8")], []),
	test_helpers.case("SIV AE", [test_helpers.algorithm("AES-SIV", "ae", {})], []),
	test_helpers.case("unagreed protection", [test_helpers.algorithm("custom-protection", "key-wrap", {})], [{"ruleId": "ECCG-KP-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	# An AE primitive alone does not establish an agreed key-protection construction. The
	# current policy reports this as a possible context mismatch.
	test_helpers.case("GCM does not establish key protection", [test_helpers.algorithm("AES-GCM", "ae", {"mode": "gcm"})], [{"ruleId": "ECCG-KP-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("custom-protection", "hash", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("custom-protection", "key-wrap", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-KP-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "Key Protection"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Constructions / Key Protection"
	}
}
