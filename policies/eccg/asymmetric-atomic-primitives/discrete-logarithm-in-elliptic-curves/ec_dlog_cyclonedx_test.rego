package cbom.eccg.section_tests.ec_dlog

import data.cbom.eccg.asymmetric_atomic_primitives.ec_dlog.findings
import data.cbom.eccg.cyclonedx_test_helpers as test_helpers

# Preserve the reported CBOMkit components, including their original references
# and occurrences. Both carry secp256r1 in curve rather than ellipticCurve.
cbomkit_curve_components := [
	{
		"type": "cryptographic-asset",
		"bom-ref": "f52196ff-8e46-49d9-8d8e-a59b5cd2f377",
		"name": "ECDH",
		"evidence": {"occurrences": [
			{"location": "demo/code/cbom_crypto_demo.py", "line": 105, "offset": 23, "additionalContext": "exchange"},
			{"location": "demo/code/cbom_crypto_demo.py", "line": 106, "offset": 21, "additionalContext": "exchange"},
		]},
		"cryptoProperties": {
			"assetType": "algorithm",
			"algorithmProperties": {"primitive": "key-agree", "curve": "secp256r1", "cryptoFunctions": ["keygen"]},
			"oid": "1.3.132.1.12",
		},
	},
	{
		"type": "cryptographic-asset",
		"bom-ref": "29672e2c-2b89-47cc-86d3-b1fc28623c32",
		"name": "SHA256withECDSA",
		"evidence": {"occurrences": [
			{"location": "demo/code/cbom_crypto_demo.py", "line": 132, "offset": 16, "additionalContext": "sign"},
		]},
		"cryptoProperties": {
			"assetType": "algorithm",
			"algorithmProperties": {"primitive": "signature", "curve": "secp256r1", "cryptoFunctions": ["keygen", "sign"]},
			"oid": "1.2.840.10045.4.3.2",
		},
	},
]

# Elliptic-curve parameter findings (ECCG-ECDLOG-001 and ECCG-ECDLOG-002). Registered
# agreed curves, rejected curves, missing parameters, and the NIST special-prime
# advisory are tested separately.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("provider ECDH name retains curve check", [test_helpers.algorithm("provider-ECDH-P256", "key-agree", {})], [{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("provider ECIES name requires curve metadata", [test_helpers.algorithm("prefix-ECIES", "pke", {})], [{"ruleId": "ECCG-ECDLOG-001", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("ECDSA construction cannot approve secp256k1", [test_helpers.algorithm("ECDSA-secp256k1-SHA256", "signature", {"ellipticCurve": "secg/secp256k1"})], [{"ruleId": "ECCG-ECDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	# These reported components must yield the NIST SpecialP advisory instead of
	# ECCG-ECDLOG-001. The combined case also checks attribution and deduplication.
	test_helpers.case("CBOMkit ECDH curve field", [cbomkit_curve_components[0]], [{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "f52196ff-8e46-49d9-8d8e-a59b5cd2f377", "curve": "NIST P-256"}]),
	test_helpers.case("CBOMkit ECDSA curve field", [cbomkit_curve_components[1]], [{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "29672e2c-2b89-47cc-86d3-b1fc28623c32", "curve": "NIST P-256"}]),
	test_helpers.case("CBOMkit ECDH and ECDSA curve fields", cbomkit_curve_components, [
		{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "f52196ff-8e46-49d9-8d8e-a59b5cd2f377", "curve": "NIST P-256"},
		{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "29672e2c-2b89-47cc-86d3-b1fc28623c32", "curve": "NIST P-256"},
	]),
	# Compatibility must preserve rejection and precedence rather than granting
	# agreement merely because a legacy field or a fixed-curve OID is present.
	test_helpers.case("legacy curve outside allowlist", [test_helpers.algorithm("ECDH", "key-agree", {"curve": "secp256k1"})], [{"ruleId": "ECCG-ECDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test", "curve": "secp256k1"}]),
	test_helpers.case("registry curve overrides legacy curve", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "secg/secp256k1", "curve": "secp256r1"})], [{"ruleId": "ECCG-ECDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test", "curve": "secg/secp256k1"}]),
	test_helpers.case("legacy curve overrides fixed curve inference", [test_helpers.with_oid(test_helpers.algorithm("Ed25519", "signature", {"curve": "secp256k1"}), "1.3.101.112")], [{"ruleId": "ECCG-ECDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test", "curve": "secp256k1"}]),
	test_helpers.case("agreed brainpool/brainpoolP256r1", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "brainpool/brainpoolP256r1"})], []),
	test_helpers.case("agreed brainpool/brainpoolP384r1", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "brainpool/brainpoolP384r1"})], []),
	test_helpers.case("agreed brainpool/brainpoolP512r1", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "brainpool/brainpoolP512r1"})], []),
	test_helpers.case("agreed anssi/FRP256v1", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "anssi/FRP256v1"})], []),
	test_helpers.case("agreed other/Curve25519", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "other/Curve25519"})], []),
	test_helpers.case("agreed other/Curve448", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "other/Curve448"})], []),
	# These NIST curves are agreed but retain the SpecialP operational warning.
	test_helpers.case("special prime nist/P-256", [test_helpers.algorithm("ECDSA", "signature", {"ellipticCurve": "nist/P-256"})], [{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("special prime nist/P-384", [test_helpers.algorithm("ECDSA", "signature", {"ellipticCurve": "nist/P-384"})], [{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("special prime nist/P-521", [test_helpers.algorithm("ECDSA", "signature", {"ellipticCurve": "nist/P-521"})], [{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("non agreed curve", [test_helpers.algorithm("ECDH", "key-agree", {"ellipticCurve": "secg/secp256k1"})], [{"ruleId": "ECCG-ECDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test", "curve": "secg/secp256k1"}]),
	# Missing curve evidence produces a warning, while a recognized curve outside the
	# allowlist produces a critical finding.
	test_helpers.case("missing curve", [test_helpers.algorithm("ECDH", "key-agree", {})], [{"ruleId": "ECCG-ECDLOG-001", "severity": "warning", "bomRef": "algorithm-under-test", "curve": "", "message": "EC-DLOG primitive detected, but its elliptic curve could not be determined. Supply algorithmProperties.ellipticCurve or algorithmProperties.curve to verify ECCG-ECDLOG-001."}]),
	test_helpers.case("curve from parameter set", [test_helpers.algorithm("ECDH", "key-agree", {"parameterSetIdentifier": "nist/P-256"})], [{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("Ed25519 algorithm OID", [test_helpers.with_oid(test_helpers.algorithm("opaque", "signature", {}), "1.3.101.112")], []),
	# Explicit curve metadata must remain visible even when a fixed-curve algorithm OID
	# supplies contradictory inference.
	test_helpers.case("explicit parameters override fixed curve inference", [test_helpers.with_oid(test_helpers.algorithm("Ed25519", "signature", {"ellipticCurve": "secg/secp256k1"}), "1.3.101.112")], [{"ruleId": "ECCG-ECDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("ECDSA registry family", [test_helpers.algorithm("opaque", "signature", {"algorithmFamily": "ECDSA", "ellipticCurve": "secg/secp256k1"})], [{"ruleId": "ECCG-ECDLOG-001", "severity": "critical", "bomRef": "algorithm-under-test"}]),
	test_helpers.case("non EC algorithm", [test_helpers.algorithm("RSA", "signature", {})], []),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("ECDSA", "signature", {"ellipticCurve": "nist/P-256"}), "src/crypto.py", 42)], [{"ruleId": "ECCG-ECDLOG-002", "severity": "warning", "bomRef": "algorithm-under-test"}]),
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
		finding.subsection == "EC DLOG"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Asymmetric Atomic Primitives / EC DLOG"
	}
}
