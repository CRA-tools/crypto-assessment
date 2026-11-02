package cbom.eccg.section_tests.asymmetric_encryption

import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.findings
import data.cbom.eccg.cyclonedx_test_helpers as test_helpers

# Asymmetric-encryption findings (ECCG-AS-ENC-001 through ECCG-AS-ENC-005). OAEP and
# PKCS#1 v1.5 have distinct padding advisories; unknown or unagreed schemes have a
# critical rejection.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	# An agreed RSA encryption scheme still requires padding and quantum-resistance review;
	# an empty finding set is not expected.
	test_helpers.case("OAEP advisories", [test_helpers.algorithm("RSAES-OAEP", "pke", {})], [{"ruleId": "ECCG-AS-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-005", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("PKCS1 v1.5 advisories", [test_helpers.algorithm("RSAES-PKCS1-v1_5", "pke", {})], [{"ruleId": "ECCG-AS-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-003", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-005", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unagreed raw RSA", [test_helpers.algorithm("RSA", "pke", {"padding": "raw"})], [{"ruleId": "ECCG-AS-ENC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unagreed ECIES", [test_helpers.algorithm("ECIES", "pke", {"algorithmFamily": "ECIES"})], [{"ruleId": "ECCG-AS-ENC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# Contradictory identifiers test OID precedence, then family precedence, then name
	# fallback when the OID is unrecognized.
	test_helpers.case("OAEP OID overrides family and name", [test_helpers.with_oid(test_helpers.algorithm("ECIES", "pke", {"algorithmFamily": "ECIES"}), "1.2.840.113549.1.1.7")], [{"ruleId": "ECCG-AS-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-005", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("family overrides name", [test_helpers.algorithm("ECIES", "pke", {"algorithmFamily": "RSAES-OAEP"})], [{"ruleId": "ECCG-AS-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-005", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unknown OID permits name fallback", [test_helpers.with_oid(test_helpers.algorithm("RSAES-OAEP", "pke", {}), "1.2.3.4.5")], [{"ruleId": "ECCG-AS-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-005", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("RSAES-OAEP", "signature", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("RSAES-OAEP", "pke", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-AS-ENC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-004", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-AS-ENC-005", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.section == "Asymmetric Constructions"
		finding.subsection == "Asymmetric Encryption Schemes"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Asymmetric Constructions / Asymmetric Encryption Schemes"
	}
}
