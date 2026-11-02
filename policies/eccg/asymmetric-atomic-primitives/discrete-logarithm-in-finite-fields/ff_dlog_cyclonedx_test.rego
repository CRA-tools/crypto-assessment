package cbom.eccg.section_tests.ff_dlog

import data.cbom.eccg.asymmetric_atomic_primitives.ff_dlog.findings
import data.cbom.eccg.cyclonedx_test_helpers as test_helpers

# Finite-field parameter findings (ECCG-FFDLOG-001 and ECCG-FFDLOG-002). Fixtures
# distinguish an unagreed group family, a known group below 3072 bits, and an agreed
# family whose size cannot be verified.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("agreed MODP-3072", [test_helpers.algorithm("DH", "key-agree", {"parameterSetIdentifier": "MODP-3072"})], []),
	test_helpers.case("agreed ffdhe3072", [test_helpers.algorithm("DH", "key-agree", {"parameterSetIdentifier": "ffdhe3072"})], []),
	# The minimum is inclusive: 3071 bits is rejected, while 3072 bits and larger satisfy
	# the size check.
	test_helpers.case("FFDHE bits 2048", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "2048"})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "critical", "bomRef": "algorithm-under-test", "groupBits": 2048, "minimumGroupBits": 3072}]),
	test_helpers.case("FFDHE bits 3071", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "3071"})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "critical", "bomRef": "algorithm-under-test", "groupBits": 3071, "minimumGroupBits": 3072}]),
	test_helpers.case("FFDHE bits 3072", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "3072"})], []),
	test_helpers.case("FFDHE bits 4096", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "4096"})], []),
	test_helpers.case("FFDHE bits 8192", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "8192"})], []),
	# Only a positive integral parameter identifies the group size. Missing, unknown, zero,
	# negative, and fractional values produce a warning for a recognized family.
	test_helpers.case("unknown group size ''", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": ""})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test", "classification": "inconclusive", "groupBits": ""}]),
	test_helpers.case("unknown group size 'unknown'", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "unknown"})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test", "classification": "inconclusive", "groupBits": ""}]),
	test_helpers.case("unknown group size '0'", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "0"})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test", "classification": "inconclusive", "groupBits": ""}]),
	test_helpers.case("unknown group size '-1'", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "-1"})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test", "classification": "inconclusive", "groupBits": ""}]),
	test_helpers.case("unknown group size '3072.5'", [test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "3072.5"})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test", "classification": "inconclusive", "groupBits": ""}]),
	test_helpers.case("missing group size", [test_helpers.algorithm("FFDHE", "key-agree", {})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("generic DH has no agreed group", [test_helpers.algorithm("DH", "key-agree", {})], [{"ruleId": "ECCG-FFDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("FFDH registry family", [test_helpers.algorithm("opaque", "key-agree", {"algorithmFamily": "FFDH"})], [{"ruleId": "ECCG-FFDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# Group numbers are identifiers, not bit lengths: MODP group 14 maps to 2048 bits and
	# group 15 to 3072 bits.
	test_helpers.case("IKE MODP group 14 is undersized", [test_helpers.algorithm("DH", "key-agree", {"parameterSetIdentifier": "MODP-group14"})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "critical", "bomRef": "algorithm-under-test", "groupBits": 2048}]),
	test_helpers.case("IKE MODP group 15 meets minimum", [test_helpers.algorithm("DH", "key-agree", {"parameterSetIdentifier": "MODP-group15"})], []),
	# An explicit smaller parameter set must not be hidden by a larger number in the
	# component name.
	test_helpers.case("name size cannot hide small parameters", [test_helpers.algorithm("FFDHE4096", "key-agree", {"parameterSetIdentifier": "ffdhe2048"})], [{"ruleId": "ECCG-FFDLOG-002", "severity": "critical", "bomRef": "algorithm-under-test", "groupBits": 2048}]),
	test_helpers.case("EC domain is unrelated", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "nist/P-256"})], []),
	# A domain-independent agreement name cannot by itself establish finite-field usage.
	test_helpers.case("generic MQV does not establish finite field domain", [test_helpers.algorithm("MQV", "key-agree", {"algorithmFamily": "MQV"})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("FFDHE", "key-agree", {"parameterSetIdentifier": "2048"}), "src/crypto.py", 42)], [{"ruleId": "ECCG-FFDLOG-002", "severity": "critical", "bomRef": "algorithm-under-test", "groupBits": 2048, "minimumGroupBits": 3072}]),
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
		finding.subsection == "FF DLOG"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Asymmetric Atomic Primitives / FF DLOG"
	}
}
