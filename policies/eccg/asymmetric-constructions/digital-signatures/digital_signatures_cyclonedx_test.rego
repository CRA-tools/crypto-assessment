package cbom.eccg.section_tests.digital_signatures

import data.cbom.eccg.asymmetric_constructions.digital_signatures.findings
import data.cbom.eccg.cyclonedx_test_helpers as test_helpers

# Signature agreement findings (ECCG-DG-001). The table’s agreed RSA,
# discrete-logarithm, lattice, and hash-based schemes produce no rejection; unagreed
# schemes remain critical.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("ECDSA with SHA3 in JCA form", [test_helpers.algorithm("SHA3-256withECDSA", "signature", {})], []),
	test_helpers.case("ECDSA with SHA3 suffix", [test_helpers.algorithm("ECDSA-SHA3-256", "signature", {})], []),
	test_helpers.case("ECDSA curve and hash are separate parameters", [test_helpers.algorithm("ECDSA-secp256r1-SHA3-256", "signature", {})], []),
	test_helpers.case("PSS with SHA3", [test_helpers.algorithm("RSA-PSS-SHA3-256", "signature", {})], []),
	test_helpers.case("PSS with non-SHA hash label", [test_helpers.algorithm("RSA-PSS-BLAKE2b-256", "signature", {})], []),
	test_helpers.case("PSS with hash and MGF in JCA form", [test_helpers.algorithm("SHA3-256withRSAandMGF1", "signature", {})], []),
	test_helpers.case("PKCS1 v1.5 with SHA3 remains acceptable", [test_helpers.algorithm("SHA3-256withRSA", "signature", {})], []),
	test_helpers.case("PKCS1 v1.5 with parameterized name", [test_helpers.algorithm("RSA-PKCS1-1.5-SHA3-256-3072", "signature", {})], []),
	test_helpers.case("DSA with SHA3", [test_helpers.algorithm("SHA3-256withDSA", "signature", {})], []),
	test_helpers.case("KCDSA with hash suffix", [test_helpers.algorithm("KCDSA-SHA3-256", "signature", {})], []),
	test_helpers.case("EC KCDSA with hash suffix", [test_helpers.algorithm("EC-KCDSA-SHA3-256", "signature", {})], []),
	test_helpers.case("EC GDSA with hash suffix", [test_helpers.algorithm("EC-GDSA-SHA3-256", "signature", {})], []),
	test_helpers.case("EC Schnorr with hash suffix", [test_helpers.algorithm("EC-Schnorr-SHA3-256", "signature", {})], []),
	test_helpers.case("Schnorr with parameters", [test_helpers.algorithm("Schnorr-SHA256-3072", "signature", {})], []),
	test_helpers.case("Deterministic ECDSA with parameters", [test_helpers.algorithm("Deterministic-ECDSA-SHA3-256", "signature", {})], []),
	test_helpers.case("EdDSA with context suffix", [test_helpers.algorithm("Ed25519-ctx", "signature", {})], []),
	test_helpers.case("LMS construction recognized before parameter review", [test_helpers.algorithm("LMS-SHA256-M32-H10", "signature", {})], []),
	test_helpers.case("ECDSA recognition is independent of curve approval", [test_helpers.algorithm("ECDSA-secp256k1-SHA256", "signature", {"ellipticCurve": "secg/secp256k1"})], []),
	# These cases assess signature-scheme agreement only. Other sections may independently
	# report modulus or curve findings for the same asset.
	test_helpers.case("agreed RSA-PSS", [test_helpers.algorithm("RSA-PSS", "signature", {})], []),
	test_helpers.case("agreed RSASSA-PKCS1-v1_5", [test_helpers.algorithm("RSASSA-PKCS1-v1_5", "signature", {})], []),
	test_helpers.case("agreed KCDSA", [test_helpers.algorithm("KCDSA", "signature", {})], []),
	test_helpers.case("agreed Schnorr", [test_helpers.algorithm("Schnorr", "signature", {})], []),
	test_helpers.case("agreed DSA", [test_helpers.algorithm("DSA", "signature", {})], []),
	test_helpers.case("agreed EC-KCDSA", [test_helpers.algorithm("EC-KCDSA", "signature", {})], []),
	test_helpers.case("agreed ECDSA", [test_helpers.algorithm("ECDSA", "signature", {})], []),
	test_helpers.case("agreed ECGDSA", [test_helpers.algorithm("ECGDSA", "signature", {})], []),
	test_helpers.case("agreed ECSchnorr", [test_helpers.algorithm("ECSchnorr", "signature", {})], []),
	test_helpers.case("agreed Deterministic ECDSA", [test_helpers.algorithm("Deterministic ECDSA", "signature", {})], []),
	test_helpers.case("agreed EdDSA", [test_helpers.algorithm("EdDSA", "signature", {})], []),
	test_helpers.case("agreed ML-DSA", [test_helpers.algorithm("ML-DSA", "signature", {})], []),
	test_helpers.case("agreed XMSS", [test_helpers.algorithm("XMSS", "signature", {})], []),
	test_helpers.case("agreed LMS", [test_helpers.algorithm("LMS", "signature", {})], []),
	test_helpers.case("agreed SLH-DSA", [test_helpers.algorithm("SLH-DSA", "signature", {})], []),
	test_helpers.case("unagreed Falcon", [test_helpers.algorithm("Falcon", "signature", {})], [{"ruleId": "ECCG-DG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("unagreed registry family", [test_helpers.algorithm("ML-DSA", "signature", {"algorithmFamily": "SM2"})], [{"ruleId": "ECCG-DG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# An agreed registered OID overrides contradictory family and name labels; an unknown
	# OID allows family fallback.
	test_helpers.case("signature OID overrides family and name", [test_helpers.with_oid(test_helpers.algorithm("Falcon", "signature", {"algorithmFamily": "SM2"}), "1.2.840.10045.4.3.2")], []),
	test_helpers.case("unknown OID permits family fallback", [test_helpers.with_oid(test_helpers.algorithm("Falcon", "signature", {"algorithmFamily": "ML-DSA"}), "1.2.3.4.5")], []),
	test_helpers.case("different primitive", [test_helpers.algorithm("Falcon", "hash", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("Falcon", "signature", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-DG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "Digital Signature Schemes"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Asymmetric Constructions / Digital Signature Schemes"
	}
}
