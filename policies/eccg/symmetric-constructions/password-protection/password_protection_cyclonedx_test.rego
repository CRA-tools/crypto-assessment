package cbom.eccg.section_tests.password_protection

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_constructions.password_hashing.findings

# Password-protection findings (ECCG-PWH-001 through ECCG-PWH-003). PBKDF2 and Argon2id
# receive their parameter advisories; other KDFs receive medium review findings.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	# These warnings request parameter verification; the CBOM does not prove iteration
	# count, salt generation, or Argon2 memory use.
	test_helpers.case("PBKDF2 iteration and salt notes", [test_helpers.algorithm("PBKDF2", "kdf", {})], [{"ruleId": "ECCG-PWH-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("Argon2id parameter note", [test_helpers.algorithm("Argon2id", "kdf", {})], [{"ruleId": "ECCG-PWH-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("PBKDF2 OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "kdf", {}), "1.2.840.113549.1.5.12")], [{"ruleId": "ECCG-PWH-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("PBKDF2 registry family", [test_helpers.algorithm("opaque", "kdf", {"algorithmFamily": "PBKDF2"})], [{"ruleId": "ECCG-PWH-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unagreed scrypt", [test_helpers.algorithm("scrypt", "kdf", {})], [{"ruleId": "ECCG-PWH-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	# The shared kdf primitive cannot distinguish password hashing from general derivation.
	# HKDF therefore exposes this section’s documented context limitation.
	test_helpers.case("generic KDF context cannot establish password protection", [test_helpers.algorithm("HKDF", "kdf", {})], [{"ruleId": "ECCG-PWH-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("PBKDF2", "hash", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("PBKDF2", "kdf", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-PWH-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "Password Hashing"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Constructions / Password Hashing"
	}
}
