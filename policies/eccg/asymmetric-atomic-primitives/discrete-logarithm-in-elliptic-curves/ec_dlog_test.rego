package cbom.eccg.asymmetric_atomic_primitives.ec_dlog_test

# Focused EC-DLOG regressions isolate primitive classification, curve evidence, and
# ambiguity. Partial records and deliberately malformed values supplement the
# schema-validated documents in ec_dlog_cyclonedx_test.rego.

import data.cbom.eccg.asymmetric_atomic_primitives.ec_dlog.findings
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_eccg_canonical_ec_curve_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_eccg_ec_curve_family_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_ecdlog_curve_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.is_ecdlog_primitive
import data.cbom.eccg.compliant as assessment_compliant
import data.cbom.eccg.findings as all_findings
import data.cbom.eccg.test_type_helpers as test_types

# Use a valid key-agreement primitive unless a case supplies another category.
# Args:
#   algorithm_name: string.
#   algorithm_properties: object<string, any>; values may be malformed on purpose.
# Returns: object<string, any> (partial algorithm component), with name,
#   bom-ref, and nested cryptoProperties.algorithmProperties; no type field.
component(algorithm_name, algorithm_properties) := {
	"name": algorithm_name,
	"bom-ref": "ec-test-component",
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": object.union({"primitive": "key-agree"}, algorithm_properties),
	},
} if {
	is_string(algorithm_name)
	test_types.is_string_keyed_object(algorithm_properties)
}

# Args:
#   test_component: object<string, any> with a cryptoProperties object.
#   algorithm_oid: any JSON value; malformed values test getter fallbacks.
# Returns: object<string, any> with algorithm_oid in cryptoProperties.oid.
with_oid(test_component, algorithm_oid) := object.union(test_component, {
	"cryptoProperties": object.union(test_component.cryptoProperties, {"oid": algorithm_oid}),
}) if {
	test_types.is_string_keyed_object(test_component)
	test_types.is_string_keyed_object(test_component.cryptoProperties)
	test_types.is_json_value(algorithm_oid)
}

# Args:
#   test_component: object<string, any> (complete or partial component).
# Returns: set<object> of ECCG-ECDLOG-001 findings; may be empty.
# Locals:
#   section_findings, curve_rule_findings: set<object> of findings.
#   finding: object (one finding with a string ruleId).
curve_findings(test_component) := curve_rule_findings if {
	test_types.is_string_keyed_object(test_component)
	section_findings := findings with input as {"components": [test_component]}
	is_set(section_findings)
	test_types.is_findings(section_findings)
	curve_rule_findings := {finding |
		some finding in section_findings
		finding.ruleId == "ECCG-ECDLOG-001"
	}
}

# Args:
#   test_component: object<string, any> (complete or partial component).
# Returns: object (one ECCG-ECDLOG-001 finding); undefined unless exactly one exists.
# Locals:
#   curve_rule_findings: set<object> of findings.
#   finding: object (the sole finding).
only_curve_finding(test_component) := finding if {
	test_types.is_string_keyed_object(test_component)
	curve_rule_findings := curve_findings(test_component)
	count(curve_rule_findings) == 1
	some finding in curve_rule_findings
}

# Every listed curve alias must avoid the curve-rejection rule; separate NIST advisory
# findings may still exist.
test_recommended_curves_and_aliases_are_allowed if {
	every curve_value in [
		"BrainpoolP256r1", "BrainpoolP384r1", "BrainpoolP512r1",
		"brainpool/brainpoolP256r1", "brainpool/brainpoolP384r1", "brainpool/brainpoolP512r1",
		"NIST P-256", "NIST P-384", "NIST P-521",
		"nist/P-256", "nist/P-384", "nist/P-521", "P-256", "P-384", "P-521",
		"secg/secp256r1", "secg/secp384r1", "secg/secp521r1",
		"secp256r1", "secp384r1", "secp521r1", "x962/prime256v1", "prime256v1",
		"FRP256v1", "anssi/FRP256v1", " NIST_p-256 ", "BRAINPOOLP512R1",
		"Curve25519", "other/Curve25519", "Curve448", "other/Curve448",
		"X25519", "X448", "Ed25519", "other/Ed25519", "Ed448", "other/Ed448",
		"Edwards25519", "Edwards448", " OTHER/ed25519 ",
	] {
		count(curve_findings(component("ECDH", {"ellipticCurve": curve_value}))) == 0
	}
}

# Known non-agreed and unknown explicit curves must produce a critical finding retaining
# the normalized curve and allowed-curve list.
test_curves_outside_the_allowlist_are_rejected if {
	every curve_value in [
		"secp256k1", "secg/secp256k1", "nist/P-192", "nist/P-224", "nist/B-283", "nist/K-283",
		"brainpoolP256t1", "brainpoolP160r1", "SM2", "unknown", "custom-curve",
		"Curve25519-extra", "Curve448-extra", "Ed25519-extra", "Ed448-extra",
		"secp256r1-extra", "brainpoolP256r1-extra",
	] {
		finding := only_curve_finding(component("ECDH", {"ellipticCurve": curve_value}))
		finding.severity == "critical"
		finding.curve == lower(curve_value)
		{allowed_curve | some allowed_curve in finding.allowedCurves} == {
			"BrainpoolP256r1", "BrainpoolP384r1", "BrainpoolP512r1",
			"NIST P-256", "NIST P-384", "NIST P-521", "FRP256v1",
			"Curve25519", "Curve448",
		}
	}
}

# Absent or malformed curve metadata must produce a warning, distinct from a known
# non-agreed curve.
test_missing_or_invalid_curve_data_is_inconclusive if {
	every curve_value in ["", null, 256, true, [], {}] {
		finding := only_curve_finding(component("ECDH", {"ellipticCurve": curve_value}))
		finding.severity == "warning"
		finding.curve == ""
	}

	finding := only_curve_finding(component("ECDSA", {"primitive": "signature"}))
	finding.severity == "warning"
}

# The explicit ellipticCurve field wins over both an approved and an unapproved curve
# embedded in the name.
test_explicit_curve_takes_precedence_over_component_name if {
	finding := only_curve_finding(component("ECDH-nist/P-256", {"ellipticCurve": "secp256k1"}))
	finding.curve == "secp256k1"
	finding.severity == "critical"
	count(curve_findings(component("ECDH-secp256k1", {"ellipticCurve": "nist/P-256"}))) == 0
}

# When curve metadata is absent, recognized name tokens supply the curve; rejected
# curves must still reach assessment.
test_curve_name_fallback_uses_shared_getter if {
	every algorithm_name in ["ECDH-BrainpoolP256r1", "ECDSA-nist/P-384", "ECDH-FRP256v1", "X25519", "X448", "Ed25519", "Ed448"] {
		count(curve_findings(component(algorithm_name, {}))) == 0
	}
	every algorithm_name in ["ECDH-secp256k1", "ECDSA-secp256k1"] {
		finding := only_curve_finding(component(algorithm_name, {}))
		finding.severity == "critical"
	}
}

# A recognized EC algorithm family activates curve assessment even when the name is
# opaque.
test_family_classification_without_a_recognized_name if {
	finding := only_curve_finding(component("custom name", {"algorithmFamily": "ECDH", "ellipticCurve": "secp256k1"}))
	finding.severity == "critical"
	every algorithm_family in ["EC-DLOG", "ECDH", "ECDHE", "ECDSA", "EdDSA", "ECIES"] {
		missing_curve_finding := only_curve_finding(component("custom name", {"algorithmFamily": algorithm_family}))
		missing_curve_finding.severity == "warning"
	}
}

# Registered EC algorithm OIDs must activate the same curve check without relying on
# family or name labels.
test_oid_classification_without_recognized_family_or_name if {
	every algorithm_oid in [
		"1.2.840.10045.2.1", "1.3.132.1.12", "1.3.132.1.13",
		"1.2.840.10045.4.1", "1.2.840.10045.4.3.1", "1.2.840.10045.4.3.2",
		"1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4",
		"1.3.101.110", "1.3.101.111", "1.3.101.112", "1.3.101.113",
	] {
		test_component := with_oid(component("custom name", {"algorithmFamily": "custom family", "ellipticCurve": "secp256k1"}), algorithm_oid)
		finding := only_curve_finding(test_component)
		finding.severity == "critical"
	}
}

# An EC public-key OID identifies the mathematical domain but does not supply a
# particular curve.
test_generic_ec_oid_does_not_imply_an_agreed_curve if {
	test_component := with_oid(component("custom name", {}), "1.2.840.10045.2.1")
	finding := only_curve_finding(test_component)
	finding.severity == "warning"
	finding.curve == ""
}

# Missing, unrecognized, and malformed OIDs must permit a usable EC family to identify
# the primitive.
test_family_fallback_for_missing_unknown_or_invalid_oid if {
	every algorithm_oid in ["", "1.2.3.4.5", null, 123, true, [], {}] {
		test_component := with_oid(component("custom name", {"algorithmFamily": "ec_dsa", "ellipticCurve": "secp256k1"}), algorithm_oid)
		finding := only_curve_finding(test_component)
		finding.severity == "critical"
	}
	component_without_name := object.remove(component("", {"algorithmFamily": "ECDH", "ellipticCurve": "secp256k1"}), {"name"})
	finding := only_curve_finding(component_without_name)
	finding.severity == "critical"
}

# Recognized EC names and parameterized aliases are the remaining evidence when neither
# OID nor family identifies the primitive.
test_name_fallback_for_unknown_oid_and_family if {
	every algorithm_name in [
		"EC-DLOG", "ECDH", "ECDHE", "ECMQV", "ECDSA", "EdDSA", "ECIES", "EC-ElGamal",
		"X25519", "X448", "Ed25519", "Ed448", "SHA256withECDSA", "ECDSAwithSHA384",
		"ECDH-secp256k1", "ECDSA_SHA256", "ECDSA/secp256k1", " ecdsa ",
	] {
		test_component := with_oid(component(algorithm_name, {"algorithmFamily": "custom family", "ellipticCurve": "secp256k1"}), "1.2.3.4.5")
		finding := only_curve_finding(test_component)
		finding.severity == "critical"
	}
}

# A curve label or nonstandard primitive string alone must not classify an otherwise
# unidentified algorithm as EC-DLOG.
test_curve_and_primitive_metadata_do_not_replace_algorithm_classification if {
	every algorithm_properties in [
		{"ellipticCurve": "secp256k1"},
		{"ellipticCurve": "nist/P-256"},
		{"primitive": "EC-DLOG"},
		{"primitive": "key-agree", "ellipticCurve": "secp256k1"},
	] {
		actual_findings := findings with input as {"components": [component("custom name", algorithm_properties)]}
		count(actual_findings) == 0
	}
}

# Misleading name fragments and unrelated asset categories must not create EC findings.
test_partial_identifier_matches_and_non_crypto_assets_are_excluded if {
	every algorithm_name in ["notECDSA", "myECDHprovider", "ECDSAish", "X4480"] {
		count(curve_findings(component(algorithm_name, {}))) == 0
	}
	every test_component in [
		{"name": "ECDH", "type": "library"},
		{"name": "ECDH", "cryptoProperties": {"assetType": "protocol", "oid": "1.2.840.10045.2.1"}},
	] {
		count(curve_findings(test_component)) == 0
	}
}

# Algorithms outside the EC domain and an empty input must not enter EC curve
# assessment.
test_unrelated_components_have_no_ec_curve_findings if {
	every algorithm_name in ["RSA", "DH", "FFDHE", "DSA", "ML-KEM", "AES", "SHA-256"] {
		count(curve_findings(component(algorithm_name, {}))) == 0
	}
	findings_for_empty_input := findings with input as {}
	count(findings_for_empty_input) == 0
}

# An agreed NIST curve still emits the SpecialP warning with its canonical curve label
# and note.
test_nist_special_p_note_is_preserved if {
	actual_findings := findings with input as {"components": [component("ECDH", {"ellipticCurve": "secg/secp256r1"})]}
	count(actual_findings) == 1
	some finding in actual_findings
	finding.ruleId == "ECCG-ECDLOG-002"
	finding.severity == "warning"
	finding.curve == "NIST P-256"
	finding.note.title == "Special P"
}

# A rejected curve must appear once in the main result with the correct section, source
# component, and compliance effect.
test_curve_violation_reaches_the_top_level if {
	test_components := [component("ECDH", {"ellipticCurve": "secp256k1"})]
	aggregate_findings := all_findings with input as {"components": test_components}
	curve_violations := {finding |
		some finding in aggregate_findings
		finding.ruleId == "ECCG-ECDLOG-001"
	}
	count(curve_violations) == 1
	some finding in curve_violations
	finding.section == "Asymmetric Atomic Primitives"
	finding.subsection == "EC DLOG"
	finding.bomRef == "ec-test-component"
	finding.severity == "critical"
	is_assessment_compliant := assessment_compliant with input as {"components": test_components}
	is_assessment_compliant == false
}

# Montgomery and Edwards aliases must map consistently to the table’s Curve25519 and
# Curve448 parameter entries.
test_edwards_identifiers_map_to_the_table_entries if {
	every canonical_curve_name, curve_aliases in {
		"Curve25519": ["Curve25519", "other/Curve25519", "X25519", "Ed25519", "other/Ed25519", "Edwards25519"],
		"Curve448": ["Curve448", "other/Curve448", "X448", "Ed448", "other/Ed448", "Edwards448"],
	} {
		every curve_alias in curve_aliases {
			get_eccg_canonical_ec_curve_or_empty(curve_alias) == canonical_curve_name
			get_eccg_ec_curve_family_or_empty(curve_alias) == "Edwards [RFC7748]"
			count(curve_findings(component(curve_alias, {}))) == 0
		}
	}
}

# Fixed-curve algorithm OIDs and families can supply Curve25519/Curve448 when explicit
# parameters are absent.
test_edwards_curve_is_resolved_from_oid_or_family if {
	every test_case in [
		{"oid": "1.3.101.110", "family": "X25519", "curve": "Curve25519"},
		{"oid": "1.3.101.111", "family": "X448", "curve": "Curve448"},
		{"oid": "1.3.101.112", "family": "Ed25519", "curve": "Curve25519"},
		{"oid": "1.3.101.113", "family": "Ed448", "curve": "Curve448"},
	] {
		component_identified_by_oid := with_oid(component("custom name", {}), test_case.oid)
		get_ecdlog_curve_or_empty(component_identified_by_oid) == test_case.curve
		count(curve_findings(component_identified_by_oid)) == 0
		component_identified_by_family := component("custom name", {"algorithmFamily": test_case.family})
		get_ecdlog_curve_or_empty(component_identified_by_family) == test_case.curve
		count(curve_findings(component_identified_by_family)) == 0
	}
}

# Fixed-curve inference follows OID before family before name, while an explicit curve
# remains authoritative.
test_edwards_curve_evidence_precedence if {
	test_component := with_oid(component("Ed448", {"algorithmFamily": "Ed448"}), "1.3.101.112")
	get_ecdlog_curve_or_empty(test_component) == "Curve25519"
	get_ecdlog_curve_or_empty(component("Ed448", {"algorithmFamily": "Ed25519"})) == "Curve25519"

	component_with_explicit_curve := with_oid(component("Ed25519", {"algorithmFamily": "Ed25519", "ellipticCurve": "secp256k1"}), "1.3.101.112")
	finding := only_curve_finding(component_with_explicit_curve)
	finding.severity == "critical"
	finding.curve == "secp256k1"
}

# Exercise EC classification through each identifier for encryption, signatures, key
# agreement, and KEM usage.
test_supported_primitive_categories_use_oid_family_then_name if {
	every test_case in [
		{"primitive": "pke", "name": "ECIES"},
		{"primitive": "signature", "name": "ECDSA"},
		{"primitive": "signature", "name": "Ed25519"},
		{"primitive": "key-agree", "name": "ECDH"},
		{"primitive": "key-agree", "name": "X25519"},
		{"primitive": "kem", "name": "ECDH"},
	] {
		component_identified_by_oid := with_oid(component("custom name", {
			"primitive": test_case.primitive,
			"ellipticCurve": "secp256k1",
		}), "1.2.840.10045.2.1")
		component_identified_by_family := component("custom name", {
			"primitive": test_case.primitive,
			"algorithmFamily": test_case.name,
			"ellipticCurve": "secp256k1",
		})
		component_identified_by_name := component(test_case.name, {
			"primitive": test_case.primitive,
			"ellipticCurve": "secp256k1",
		})
		every test_component in [component_identified_by_oid, component_identified_by_family, component_identified_by_name] {
			is_ecdlog_primitive(test_component)
			finding := only_curve_finding(test_component)
			finding.severity == "critical"
		}
	}
}

# A supported primitive category does not make an RSA, finite-field, or lattice
# algorithm an EC construction.
test_non_ec_algorithms_in_supported_categories_are_excluded if {
	every test_case in [
		{"primitive": "pke", "name": "RSA"},
		{"primitive": "signature", "name": "RSA"},
		{"primitive": "signature", "name": "DSA"},
		{"primitive": "key-agree", "name": "FFDHE"},
		{"primitive": "kem", "name": "ML-KEM"},
	] {
		test_component := component(test_case.name, {"primitive": test_case.primitive, "algorithmFamily": test_case.name})
		not is_ecdlog_primitive(test_component)
		count(curve_findings(test_component)) == 0
	}
}

# A declared unrelated or malformed primitive must prevent EC assessment even when OID,
# family, and name all look like EC.
test_unrelated_or_invalid_primitives_override_ec_identifier_evidence if {
	every primitive_type in [
		"drbg", "mac", "block-cipher", "stream-cipher", "hash", "xof",
		"kdf", "ae", "combiner", "key-wrap", "other", "unknown",
		"EC-DLOG", "", null, 256, true, [], {},
	] {
		test_component := with_oid(component("ECDSA", {
			"primitive": primitive_type,
			"algorithmFamily": "ECDSA",
			"ellipticCurve": "secp256k1",
			"cryptoFunctions": ["sign"],
		}), "1.2.840.10045.2.1")
		not is_ecdlog_primitive(test_component)
		actual_findings := findings with input as {"components": [test_component]}
		count(actual_findings) == 0
	}
}

# EC identification cannot bypass this section’s requirement for an eligible primitive
# category.
test_missing_primitive_does_not_pass_the_candidate_check if {
	component_without_primitive := {
		"name": "ECDSA",
		"cryptoProperties": {
			"assetType": "algorithm",
			"oid": "1.2.840.10045.2.1",
			"algorithmProperties": {"algorithmFamily": "ECDSA", "ellipticCurve": "secp256k1"},
		},
	}
	not is_ecdlog_primitive(component_without_primitive)
	actual_findings := findings with input as {"components": [component_without_primitive]}
	count(actual_findings) == 0
}

# Recognized disallowed tokens lead to rejection; partial or conflicting tokens leave
# the curve unresolved and produce a warning.
test_name_extraction_distinguishes_non_agreed_and_unknown_curves if {
	every algorithm_name in ["ECDH-secp224r1", "ECDH-brainpoolP256t1"] {
		finding := only_curve_finding(component(algorithm_name, {}))
		finding.severity == "critical"
	}
	every algorithm_name in ["ECDH-secp256r10", "ECDH-Curve255190", "ECDH-secp256k1-NIST-P-256"] {
		finding := only_curve_finding(component(algorithm_name, {}))
		finding.severity == "warning"
		finding.curve == ""
	}
	every algorithm_name in ["ECDSA-P-256", "ECDH-P-384", "ECDSA-P-521", "EdDSA-Edwards25519"] {
		test_component := component(algorithm_name, {})
		is_ecdlog_primitive(test_component)
		get_ecdlog_curve_or_empty(test_component) != ""
		count(curve_findings(test_component)) == 0
	}
}

# Parameter-set curve evidence, including ambiguity, must take precedence over a
# reassuring curve in the component name.
test_parameter_set_curves_are_enforced_before_component_names if {
	rejected_parameter_finding := only_curve_finding(component("ECDH-P-256", {"parameterSetIdentifier": "secp224r1"}))
	rejected_parameter_finding.severity == "critical"
	rejected_parameter_finding.curve == "secp224r1"

	ambiguous_parameter_finding := only_curve_finding(component("ECDH-P-256", {"parameterSetIdentifier": "secp256k1/P-384"}))
	ambiguous_parameter_finding.severity == "warning"
	ambiguous_parameter_finding.curve == ""

	component_with_agreed_parameter := component("ECDH-secp256k1", {"parameterSetIdentifier": "nist/P-256"})
	get_eccg_canonical_ec_curve_or_empty(get_ecdlog_curve_or_empty(component_with_agreed_parameter)) == "NIST P-256"
	count(curve_findings(component_with_agreed_parameter)) == 0
}

# An Ed25519 identifier must not conceal an ambiguous or explicitly disallowed
# parameter-set curve.
test_edwards_curve_inference_does_not_hide_parameter_sets if {
	every test_component in [
		component("Ed25519", {"parameterSetIdentifier": "secp256k1/P-384"}),
		component("custom name", {"algorithmFamily": "Ed25519", "parameterSetIdentifier": "secp256k1/P-384"}),
		with_oid(component("custom name", {"parameterSetIdentifier": "secp256k1/P-384"}), "1.3.101.112"),
	] {
		finding := only_curve_finding(test_component)
		finding.severity == "warning"
		finding.curve == ""
	}

	component_with_explicit_parameter := with_oid(component("Ed25519", {"parameterSetIdentifier": "secp224r1"}), "1.3.101.112")
	finding := only_curve_finding(component_with_explicit_parameter)
	finding.severity == "critical"
	finding.curve == "secp224r1"
}
