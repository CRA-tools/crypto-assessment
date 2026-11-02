package cbom.eccg.section_tests.key_derivation

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_constructions.key_derivation.findings

# Key-derivation findings (ECCG-KDF-001 and ECCG-KDF-002). Agreed KDFs avoid rejection;
# PBKDF2 additionally requires review of its underlying PRF.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("agreed HKDF", [test_helpers.algorithm("HKDF", "kdf", {})], []),
	test_helpers.case("agreed ANSI-X9.63-KDF", [test_helpers.algorithm("ANSI-X9.63-KDF", "kdf", {})], []),
	test_helpers.case("agreed SP800-56A", [test_helpers.algorithm("SP800-56A", "kdf", {})], []),
	test_helpers.case("agreed SP800-56C", [test_helpers.algorithm("SP800-56C", "kdf", {})], []),
	# Recognizing PBKDF2 does not verify its PRF or how that PRF handles a long key.
	test_helpers.case("PBKDF2 PRF warning", [test_helpers.algorithm("PBKDF2-HMAC-SHA256", "kdf", {})], [{"ruleId": "ECCG-KDF-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# Opaque names ensure the OID and registry-family recognition branches are exercised.
	test_helpers.case("PBKDF2 OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "kdf", {}), "1.2.840.113549.1.5.12")], [{"ruleId": "ECCG-KDF-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HKDF registry family", [test_helpers.algorithm("opaque", "kdf", {"algorithmFamily": "HKDF"})], []),
	test_helpers.case("unagreed scrypt", [test_helpers.algorithm("scrypt", "kdf", {})], [{"ruleId": "ECCG-KDF-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unknown KDF", [test_helpers.algorithm("custom-kdf", "kdf", {})], [{"ruleId": "ECCG-KDF-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("PBKDF2", "hash", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("PBKDF2-HMAC-SHA256", "kdf", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-KDF-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "Key Derivation"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Constructions / Key Derivation"
	}
}
