package cbom.eccg.section_tests.xofs

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_atomic_primitives.xofs.xofs.findings

# Extendable-output-function findings (ECCG-XOF-001 and ECCG-XOF-002). SHAKE/cSHAKE
# recognition and the declared 256-bit output threshold are independent checks.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("SHAKE128 with output suffix", [test_helpers.algorithm("SHAKE128-256", "xof", {"parameterSetIdentifier": "256"})], []),
	test_helpers.case("SHAKE256 with output suffix", [test_helpers.algorithm("SHAKE256-512", "xof", {"parameterSetIdentifier": "512"})], []),
	test_helpers.case("cSHAKE128 with output suffix", [test_helpers.algorithm("cSHAKE128-256", "xof", {"parameterSetIdentifier": "256"})], []),
	test_helpers.case("cSHAKE256 with output suffix", [test_helpers.algorithm("cSHAKE256-512", "xof", {"parameterSetIdentifier": "512"})], []),
	test_helpers.case("SHA3 family with SHAKE output suffix", [test_helpers.algorithm("SHAKE128-256", "xof", {"algorithmFamily": "SHA-3", "parameterSetIdentifier": "256"})], []),
	test_helpers.case("XOF output advice remains independent of recognition", [test_helpers.algorithm("SHAKE128-128", "xof", {"parameterSetIdentifier": "128"})], [{"ruleId": "ECCG-XOF-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("cSHAKE variant must end before parameters", [test_helpers.algorithm("cSHAKE2560-512", "xof", {"parameterSetIdentifier": "512"})], [{"ruleId": "ECCG-XOF-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("SHA-3 family does not turn TupleHashXOF into SHAKE", [test_helpers.algorithm("TupleHashXOF256", "xof", {"algorithmFamily": "SHA-3"})], [{"ruleId": "ECCG-XOF-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("custom SHAKE composite", [test_helpers.algorithm("custom-SHAKE256", "xof", {"parameterSetIdentifier": "256"})], [{"ruleId": "ECCG-XOF-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# The number in the XOF name identifies the construction; output size is supplied
	# separately in parameterSetIdentifier.
	test_helpers.case("agreed SHAKE128", [test_helpers.algorithm("SHAKE128", "xof", {"parameterSetIdentifier": "256"})], []),
	test_helpers.case("agreed SHAKE256", [test_helpers.algorithm("SHAKE256", "xof", {"parameterSetIdentifier": "256"})], []),
	test_helpers.case("agreed cSHAKE128", [test_helpers.algorithm("cSHAKE128", "xof", {"parameterSetIdentifier": "256"})], []),
	test_helpers.case("agreed cSHAKE256", [test_helpers.algorithm("cSHAKE256", "xof", {"parameterSetIdentifier": "256"})], []),
	# Pin the inclusive 256-bit threshold and the advisory when the output size cannot be
	# read.
	test_helpers.case("output threshold '255'", [test_helpers.algorithm("SHAKE256", "xof", {"parameterSetIdentifier": "255"})], [{"ruleId": "ECCG-XOF-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("output threshold '256'", [test_helpers.algorithm("SHAKE256", "xof", {"parameterSetIdentifier": "256"})], []),
	test_helpers.case("output threshold '257'", [test_helpers.algorithm("SHAKE256", "xof", {"parameterSetIdentifier": "257"})], []),
	test_helpers.case("output threshold ''", [test_helpers.algorithm("SHAKE256", "xof", {"parameterSetIdentifier": ""})], [{"ruleId": "ECCG-XOF-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("output threshold 'unknown'", [test_helpers.algorithm("SHAKE256", "xof", {"parameterSetIdentifier": "unknown"})], [{"ruleId": "ECCG-XOF-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("known XOF OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "xof", {"parameterSetIdentifier": "256"}), "2.16.840.1.101.3.4.2.12")], []),
	test_helpers.case("unagreed BLAKE3", [test_helpers.algorithm("BLAKE3", "xof", {"algorithmFamily": "BLAKE3"})], [{"ruleId": "ECCG-XOF-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("different primitive", [test_helpers.algorithm("SHAKE256", "hash", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("SHAKE256", "xof", {"parameterSetIdentifier": "255"}), "src/crypto.py", 42)], [{"ruleId": "ECCG-XOF-002", "severity": "medium", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "XOFs"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Atomic Primitives / XOFs"
	}
}
