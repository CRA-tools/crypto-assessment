package cbom.eccg.section_tests.rsa

import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.findings
import data.cbom.eccg.cyclonedx_test_helpers as test_helpers

# RSA modulus findings (ECCG-RSA-001). Known positive integer moduli below 3000 bits are
# rejected. The current rule emits no finding for absent or invalid modulus metadata.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	# Exercise the exact 3000-bit boundary as well as common smaller and larger RSA sizes.
	test_helpers.case("RSA modulus 2048", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "2048"})], [{"ruleId": "ECCG-RSA-001", "severity": "critical", "bomRef": "algorithm-under-test", "modulusBits": 2048, "minimumModulusBits": 3000}]),
	test_helpers.case("RSA modulus 2999", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "2999"})], [{"ruleId": "ECCG-RSA-001", "severity": "critical", "bomRef": "algorithm-under-test", "modulusBits": 2999, "minimumModulusBits": 3000}]),
	test_helpers.case("RSA modulus 3000", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "3000"})], []),
	test_helpers.case("RSA modulus 3072", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "3072"})], []),
	test_helpers.case("RSA modulus 4096", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "4096"})], []),
	# These cases pin the current missing-data behavior. No finding here is not proof that
	# the modulus or public exponent satisfies the requirements.
	test_helpers.case("unverifiable modulus ''", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": ""})], []),
	test_helpers.case("unverifiable modulus 'unknown'", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "unknown"})], []),
	test_helpers.case("unverifiable modulus '0'", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "0"})], []),
	test_helpers.case("unverifiable modulus '-1'", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "-1"})], []),
	test_helpers.case("unverifiable modulus '2999.5'", [test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "2999.5"})], []),
	test_helpers.case("missing modulus", [test_helpers.algorithm("RSA", "pke", {})], []),
	# Primitive recognition must work for opaque names when a registered RSA OID or
	# signature family supplies the evidence.
	test_helpers.case("RSA algorithm OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "signature", {"parameterSetIdentifier": "2048"}), "1.2.840.113549.1.1.1")], [{"ruleId": "ECCG-RSA-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("RSA signature registry family", [test_helpers.algorithm("opaque", "signature", {"algorithmFamily": "RSASSA-PSS", "parameterSetIdentifier": "2048"})], [{"ruleId": "ECCG-RSA-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("non RSA signature", [test_helpers.algorithm("ECDSA", "signature", {"parameterSetIdentifier": "2048"})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("RSA", "pke", {"parameterSetIdentifier": "2048"}), "src/crypto.py", 42)], [{"ruleId": "ECCG-RSA-001", "severity": "critical", "bomRef": "algorithm-under-test", "modulusBits": 2048, "minimumModulusBits": 3000}]),
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
		finding.section == "Asymmetric Atomic Primitives"
		finding.subsection == "RSA Integer Factorization"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Asymmetric Atomic Primitives / RSA Integer Factorization"
	}
}
