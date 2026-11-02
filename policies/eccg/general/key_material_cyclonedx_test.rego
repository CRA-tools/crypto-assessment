package cbom.eccg.section_tests.key_material

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.general.key_detection.findings

# Direct key-material findings (ECCG-RSA-KEY-001 and ECCG-RSA-KEY-002). Fixtures nest
# material properties under cryptoProperties and use an integer size, as required by
# CycloneDX. This section is deliberately excluded from the main assessment; the
# integration suite checks that exclusion.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	# Private keys require a high-severity review; public keys produce an informational
	# finding. These are material assets, not algorithm declarations.
	test_helpers.case("private key review", [{"type": "cryptographic-asset", "bom-ref": "algorithm-under-test", "name": "private-key", "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "private-key", "size": 2048}}}], [{"ruleId": "ECCG-RSA-KEY-001", "severity": "high", "bomRef": "algorithm-under-test", "materialType": "private-key", "size": 2048}]),
	test_helpers.case("public key review", [{"type": "cryptographic-asset", "bom-ref": "algorithm-under-test", "name": "public-key", "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "public-key", "size": 2048}}}], [{"ruleId": "ECCG-RSA-KEY-002", "severity": "info", "bomRef": "algorithm-under-test", "materialType": "public-key", "size": 2048}]),
	# Secret-key material and an RSA algorithm declaration are outside these two
	# private/public-key rules.
	test_helpers.case("other key material", [{"type": "cryptographic-asset", "bom-ref": "algorithm-under-test", "name": "secret-key", "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "secret-key", "size": 2048}}}], []),
	test_helpers.case("algorithm is not key material", [test_helpers.algorithm("RSA", "pke", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence({"type": "cryptographic-asset", "bom-ref": "algorithm-under-test", "name": "private-key", "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "private-key", "size": 2048}}}, "src/crypto.py", 42)], [{"ruleId": "ECCG-RSA-KEY-001", "severity": "high", "bomRef": "algorithm-under-test", "materialType": "private-key", "size": 2048}]),
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
