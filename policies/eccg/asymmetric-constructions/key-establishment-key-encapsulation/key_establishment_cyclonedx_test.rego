package cbom.eccg.section_tests.key_establishment

import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.findings
import data.cbom.eccg.cyclonedx_test_helpers as test_helpers

# Key-establishment and KEM findings (ECCG-KEE-001 through ECCG-KEE-004). All agreed
# schemes retain the authentication advisory; ML-KEM and FrodoKEM may also require a
# parameter-size warning.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("agreed DH", [test_helpers.algorithm("DH", "key-agree", {})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed DLIES-KEM", [test_helpers.algorithm("DLIES-KEM", "key-agree", {})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed EC-DH", [test_helpers.algorithm("EC-DH", "key-agree", {})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed ECIES-KEM", [test_helpers.algorithm("ECIES-KEM", "key-agree", {})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed X25519", [test_helpers.algorithm("X25519", "key-agree", {})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed X448", [test_helpers.algorithm("X448", "key-agree", {})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# ML-KEM-512 triggers the parameter recommendation; 768 and 1024 suppress only that
	# warning, not the authentication advisory.
	test_helpers.case("ML KEM 512", [test_helpers.algorithm("ML-KEM", "kem", {"algorithmFamily": "ML-KEM", "parameterSetIdentifier": "512"})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-KEE-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("ML KEM 768", [test_helpers.algorithm("ML-KEM", "kem", {"algorithmFamily": "ML-KEM", "parameterSetIdentifier": "768"})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("ML KEM 1024", [test_helpers.algorithm("ML-KEM", "kem", {"algorithmFamily": "ML-KEM", "parameterSetIdentifier": "1024"})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# FrodoKEM-640 triggers the recommendation; 976 and 1344 suppress only the parameter
	# warning.
	test_helpers.case("FrodoKEM 640", [test_helpers.algorithm("FrodoKEM", "kem", {"parameterSetIdentifier": "640"})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-KEE-004", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("FrodoKEM 976", [test_helpers.algorithm("FrodoKEM", "kem", {"parameterSetIdentifier": "976"})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("FrodoKEM 1344", [test_helpers.algorithm("FrodoKEM", "kem", {"parameterSetIdentifier": "1344"})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("missing ML KEM parameters", [test_helpers.algorithm("ML-KEM", "kem", {"algorithmFamily": "ML-KEM"})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-KEE-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("missing FrodoKEM parameters", [test_helpers.algorithm("FrodoKEM", "kem", {})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-KEE-004", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# A nonempty invalid parameter must not be replaced by a reassuring size in the name.
	test_helpers.case("invalid parameter string", [test_helpers.algorithm("ML-KEM-1024", "kem", {"parameterSetIdentifier": "invalid"})], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-KEE-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# A parameter-specific OID takes precedence over contradictory parameter and name
	# fields.
	test_helpers.case("parameter OID overrides name", [test_helpers.with_oid(test_helpers.algorithm("ML-KEM-512", "kem", {"parameterSetIdentifier": "512"}), "2.16.840.1.101.3.4.4.2")], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# A pre-standard Kyber name does not establish FIPS 203 ML-KEM.
	test_helpers.case("unagreed Kyber", [test_helpers.algorithm("Kyber", "kem", {})], [{"ruleId": "ECCG-KEE-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("ML-KEM", "hash", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("DH", "key-agree", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-KEE-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "Key Establishment and Key Encapsulation Schemes"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Asymmetric Constructions / Key Establishment and Key Encapsulation Schemes"
	}
}
