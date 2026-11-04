package cbom.eccg.section_tests.authenticated_encryption

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.authenticated_encryption.findings

# Authenticated-encryption findings (ECCG-SEAS-001 and ECCG-SEAS-002). GCM, CCM, and EAX
# receive the challenge-management advisory; an unagreed AE construction receives a
# critical finding.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("GCM with tag and IV lengths", [test_helpers.algorithm("AES-256-GCM-128-96", "ae", {"mode": "gcm"})], [{"ruleId": "ECCG-SEAS-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("AES family and GCM mode do not hide SIV", [test_helpers.algorithm("AES-256-GCM-SIV-128-96", "ae", {"algorithmFamily": "AES", "mode": "gcm"})], [{"ruleId": "ECCG-SEAS-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("GCM-SIV does not inherit GCM agreement", [test_helpers.algorithm("AES-GCM-SIV", "ae", {"mode": "gcm"})], [{"ruleId": "ECCG-SEAS-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("custom CCM composite", [test_helpers.algorithm("AES-CCM-custom", "ae", {"mode": "ccm"})], [{"ruleId": "ECCG-SEAS-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# Agreement does not prove challenge uniqueness or length; the operational warning
	# remains for each agreed scheme.
	test_helpers.case("agreed GCM", [test_helpers.algorithm("AES-GCM", "ae", {"mode": "gcm"})], [{"ruleId": "ECCG-SEAS-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed CCM", [test_helpers.algorithm("AES-CCM", "ae", {"mode": "ccm"})], [{"ruleId": "ECCG-SEAS-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed EAX", [test_helpers.algorithm("AES-EAX", "ae", {})], [{"ruleId": "ECCG-SEAS-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unknown AE", [test_helpers.algorithm("ChaCha20-Poly1305", "ae", {})], [{"ruleId": "ECCG-SEAS-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("GCM by OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "ae", {}), "2.16.840.1.101.3.4.1.6")], [{"ruleId": "ECCG-SEAS-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("CCM by family and mode", [test_helpers.algorithm("opaque", "ae", {"algorithmFamily": "AES", "mode": "ccm"})], [{"ruleId": "ECCG-SEAS-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("AES-GCM", "block-cipher", {"mode": "gcm"})], []),
	# This also guards the build_finding call: passing a name or argument list instead of
	# the component would lose its bom-ref and source references.
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("AES-GCM", "ae", {"mode": "gcm"}), "src/crypto.py", 42)], [{"ruleId": "ECCG-SEAS-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "Authenticated Encryption"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Constructions / Authenticated Encryption"
	}
}
