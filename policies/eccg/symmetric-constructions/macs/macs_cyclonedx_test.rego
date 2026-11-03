package cbom.eccg.section_tests.macs

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_constructions.mac.findings

# MAC agreement and operational advisories, including ECCG-MAC, ECCG-HMAC, ECCG-CBC-MAC,
# and ECCG-GMAC findings. Cases also exercise HMAC-SHA1 expiry and the encryption/MAC
# source-proximity heuristic.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("KMAC128 with output length", [test_helpers.algorithm("KMAC128-256", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"},{"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("KMAC256 with output length", [test_helpers.algorithm("KMAC256-512", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"},{"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("KMAC output length with SHA3 family", [test_helpers.algorithm("KMAC128-256", "mac", {"algorithmFamily": "SHA-3"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"},{"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("KMACXOF is a distinct construction", [test_helpers.algorithm("KMACXOF128-256", "mac", {"algorithmFamily": "SHA-3"})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("KMAC variant must end before parameters", [test_helpers.algorithm("KMAC1280-256", "mac", {})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC registry family with opaque name", [test_helpers.algorithm("opaque", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA224 name", [test_helpers.algorithm("HMAC-SHA224", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA224 with registry family", [test_helpers.algorithm("HMAC-SHA224", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA224 OID with opaque name", [test_helpers.with_oid(test_helpers.algorithm("opaque", "mac", {}), "1.2.840.113549.2.8")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA512/224 OID with opaque name", [test_helpers.with_oid(test_helpers.algorithm("opaque", "mac", {}), "1.2.840.113549.2.12")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA3-224 OID with opaque name", [test_helpers.with_oid(test_helpers.algorithm("opaque", "mac", {}), "2.16.840.1.101.3.4.2.13")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	object.union(test_helpers.case("HMAC SHA1 OID legacy final day", [test_helpers.with_oid(test_helpers.algorithm("opaque", "mac", {}), "1.2.840.113549.2.7")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2030-12-31T23:59:59Z")}),
	object.union(test_helpers.case("HMAC SHA1 OID still expires despite contradictory name", [test_helpers.with_oid(test_helpers.algorithm("HMAC-SHA224", "mac", {"algorithmFamily": "HMAC"}), "1.2.840.113549.2.7")], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2031-01-01T00:00:00Z")}),
	object.union(test_helpers.case("HMAC SHA224 OID takes precedence over SHA1 name", [test_helpers.with_oid(test_helpers.algorithm("HMAC-SHA1", "mac", {"algorithmFamily": "HMAC"}), "1.2.840.113549.2.8")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2031-01-01T00:00:00Z")}),
	test_helpers.case("KMAC registry family with opaque name", [test_helpers.algorithm("opaque", "mac", {"algorithmFamily": "SHA-3"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unknown OID falls back to KMAC registry family", [test_helpers.with_oid(test_helpers.algorithm("opaque", "mac", {"algorithmFamily": "SHA-3"}), "1.2.3.4")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("KMAC OID with opaque name", [test_helpers.with_oid(test_helpers.algorithm("opaque", "mac", {}), "2.16.840.1.101.3.4.2.19")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("KMAC OID takes precedence over contradictory family and name", [test_helpers.with_oid(test_helpers.algorithm("KMAC512", "mac", {"algorithmFamily": "HMAC"}), "2.16.840.1.101.3.4.2.19")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA512-224 name", [test_helpers.algorithm("HMAC-SHA512-224", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC family recognizes dashed SHA512-224", [test_helpers.algorithm("HMAC-SHA512-224", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("SHA512 with an unambiguous tag length", [test_helpers.algorithm("HMAC-SHA512-128", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("provider HMAC name retains advisories", [test_helpers.algorithm("provider-HMAC-SHA256", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("provider HMAC name with tag length", [test_helpers.algorithm("provider-HMAC-SHA256-128", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("provider HMAC SHA512/256 is recognized", [test_helpers.algorithm("provider-HMAC-SHA512/256", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("provider HMAC SHA512/224 is recognized", [test_helpers.algorithm("provider-HMAC-SHA512/224", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("provider HMAC SHA512/224 with tag length", [test_helpers.algorithm("provider-HMAC-SHA512/224-128", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("provider HMAC MD5 is recognized", [test_helpers.algorithm("provider-HMAC-MD5", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	object.union(test_helpers.case("provider HMAC SHA1 still expires", [test_helpers.algorithm("provider-HMAC-SHA1", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2031-01-01T00:00:00Z")}),
	object.union(test_helpers.case("provider HMAC SHA1 tag still expires", [test_helpers.algorithm("provider-HMAC-SHA1-96", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2031-01-01T00:00:00Z")}),
	object.union(test_helpers.case("HMAC SHA1 tag suffix does not bypass expiry", [test_helpers.algorithm("HMAC-SHA1-96", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2031-01-01T00:00:00Z")}),
	test_helpers.case("HMAC family recognizes SHA512/224", [test_helpers.algorithm("HMAC-SHA512/224", "mac", {"algorithmFamily": "HMAC"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("SHA-3 family cannot approve KMAC512", [test_helpers.algorithm("KMAC512", "mac", {"algorithmFamily": "SHA-3"})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("CMAC with cipher and output length", [test_helpers.algorithm("CMAC-AES-256-128", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC with output length", [test_helpers.algorithm("HMAC-SHA256-128", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA512/224 with output length", [test_helpers.algorithm("HMAC-SHA512/224-128", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA-512/224", [test_helpers.algorithm("HMAC-SHA512/224", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("custom CMAC composite", [test_helpers.algorithm("CMAC-custom", "mac", {})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC SHA256", [test_helpers.algorithm("HMAC-SHA256", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("KMAC128", [test_helpers.algorithm("KMAC128", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("KMAC256", [test_helpers.algorithm("KMAC256", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("CMAC", [test_helpers.algorithm("CMAC", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("CBC MAC fixed input", [test_helpers.algorithm("CBC-MAC", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-CBC-MAC-001", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# The current policy emits the general truncation advisory as well as all three
	# GMAC-specific warnings.
	test_helpers.case("GMAC notes", [test_helpers.algorithm("GMAC", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-GMAC-001", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-GMAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-GMAC-003", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unagreed Poly1305", [test_helpers.algorithm("Poly1305", "mac", {})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("HMAC by OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "mac", {}), "1.2.840.113549.2.9")], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("CMAC by registry family", [test_helpers.algorithm("opaque", "mac", {"algorithmFamily": "CMAC"})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	# Test the last second of 2030 and the start of 2031. A generic HMAC match must not
	# bypass the SHA1-specific expiry.
	object.union(test_helpers.case("HMAC SHA1 legacy final day", [test_helpers.algorithm("HMAC-SHA1", "mac", {})], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2030-12-31T23:59:59Z")}),
	object.union(test_helpers.case("HMAC SHA1 after cutoff", [test_helpers.algorithm("HMAC-SHA1", "mac", {})], [{"ruleId": "ECCG-MAC-001", "severity": "critical", "bomRef": "algorithm-under-test"}]), {"evaluationTime": time.parse_rfc3339_ns("2031-01-01T00:00:00Z")}),
	test_helpers.case("different primitive", [test_helpers.algorithm("HMAC-SHA256", "hash", {})], []),
	# The same-file window includes a distance of 15 lines and excludes 16. The warning
	# shares ECCG-MAC-001 with the rejection rule, so severity and relatedComponent
	# distinguish the findings.
	test_helpers.case("composition proximity 15 lines", [test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("AES-CBC", "block-cipher", {}), "encryption"), "src/combined.py", 20), test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("HMAC-SHA256", "mac", {}), "mac"), "src/combined.py", 35)], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "mac"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "mac"}, {"ruleId": "ECCG-MAC-001", "severity": "warning", "bomRef": "encryption", "relatedComponent": "mac", "method": "occurrence-proximity", "heuristic": true}]),
	test_helpers.case("composition proximity 16 lines", [test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("AES-CBC", "block-cipher", {}), "encryption"), "src/combined.py", 20), test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("HMAC-SHA256", "mac", {}), "mac"), "src/combined.py", 36)], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "mac"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "mac"}]),
	# Matching line numbers in separate files must not establish a possible composition.
	test_helpers.case("different files are not a composition", [test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("AES-CBC", "block-cipher", {}), "encryption"), "src/combined.py", 20), test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("HMAC-SHA256", "mac", {}), "mac"), "src/other.py", 20)], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "mac"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "mac"}]),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("HMAC-SHA256", "mac", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-MAC-002", "severity": "warning", "bomRef": "algorithm-under-test"}, {"ruleId": "ECCG-HMAC-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "Mac"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Constructions / Mac"
	}
}
