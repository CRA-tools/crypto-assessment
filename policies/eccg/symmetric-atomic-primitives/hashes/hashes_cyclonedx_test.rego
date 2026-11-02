package cbom.eccg.section_tests.hashes

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_atomic_primitives.hashes.hash_primitives.findings

# Hash-function findings (ECCG-HASH-001 and ECCG-HASH-002). Concrete agreed hashes are
# checked separately from the advisory on an output size below 384 bits.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	# Agreed SHA-2 and SHA-3 variants may still emit the quantum advisory for a short
	# declared output.
	test_helpers.case("agreed SHA-256", [test_helpers.algorithm("SHA-256", "hash", {"parameterSetIdentifier": "256"})], [{"ruleId": "ECCG-HASH-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed SHA-384", [test_helpers.algorithm("SHA-384", "hash", {"parameterSetIdentifier": "384"})], []),
	test_helpers.case("agreed SHA-512", [test_helpers.algorithm("SHA-512", "hash", {"parameterSetIdentifier": "512"})], []),
	test_helpers.case("agreed SHA-512/256", [test_helpers.algorithm("SHA-512/256", "hash", {"parameterSetIdentifier": "256"})], [{"ruleId": "ECCG-HASH-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed SHA3-256", [test_helpers.algorithm("SHA3-256", "hash", {"parameterSetIdentifier": "256"})], [{"ruleId": "ECCG-HASH-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("agreed SHA3-384", [test_helpers.algorithm("SHA3-384", "hash", {"parameterSetIdentifier": "384"})], []),
	test_helpers.case("agreed SHA3-512", [test_helpers.algorithm("SHA3-512", "hash", {"parameterSetIdentifier": "512"})], []),
	# Test just below, at, and above 384 bits. Empty and unknown parameter strings cannot
	# establish that the threshold is met.
	test_helpers.case("output threshold '383'", [test_helpers.algorithm("SHA-384", "hash", {"parameterSetIdentifier": "383"})], [{"ruleId": "ECCG-HASH-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("output threshold '384'", [test_helpers.algorithm("SHA-384", "hash", {"parameterSetIdentifier": "384"})], []),
	test_helpers.case("output threshold '385'", [test_helpers.algorithm("SHA-384", "hash", {"parameterSetIdentifier": "385"})], []),
	test_helpers.case("output threshold ''", [test_helpers.algorithm("SHA-384", "hash", {"parameterSetIdentifier": ""})], [{"ruleId": "ECCG-HASH-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("output threshold 'unknown'", [test_helpers.algorithm("SHA-384", "hash", {"parameterSetIdentifier": "unknown"})], [{"ruleId": "ECCG-HASH-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("known hash OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "hash", {"parameterSetIdentifier": "384"}), "2.16.840.1.101.3.4.2.2")], []),
	test_helpers.case("unagreed MD5", [test_helpers.algorithm("MD5", "hash", {"algorithmFamily": "MD5"})], [{"ruleId": "ECCG-HASH-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unidentified hash", [test_helpers.algorithm("unidentified", "hash", {})], [{"ruleId": "ECCG-HASH-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# The registry family describes several hashes and cannot select a concrete agreed
	# function by itself.
	test_helpers.case("generic SHA-2 family is insufficient", [test_helpers.algorithm("unidentified", "hash", {"algorithmFamily": "SHA-2"})], [{"ruleId": "ECCG-HASH-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("SHA-256", "mac", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("SHA-256", "hash", {"parameterSetIdentifier": "256"}), "src/crypto.py", 42)], [{"ruleId": "ECCG-HASH-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
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
		finding.section == "Symmetric Atomic Primitives"
		finding.subsection == "Hash Primitives"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Atomic Primitives / Hash Primitives"
	}
}
