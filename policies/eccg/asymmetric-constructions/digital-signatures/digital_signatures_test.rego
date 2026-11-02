package cbom.eccg.asymmetric_constructions.digital_signatures_test

# Focused signature regressions cover aliases, conflicting identifiers, and operation
# scope. Some inputs intentionally violate schema enums or types to test fallback
# behavior; the separate CycloneDX suite validates complete documents.

import data.cbom.eccg.asymmetric_constructions.digital_signatures.compliant
import data.cbom.eccg.asymmetric_constructions.digital_signatures.findings
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.get_digital_signature_scheme_or_empty as get_signature_scheme
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.is_digital_signature_component
import data.cbom.eccg.findings as all_findings
import data.cbom.eccg.test_type_helpers as test_types

# Args:
#   algorithm_name: string.
#   algorithm_family, algorithm_oid: any JSON value; normally strings,
#       with malformed values supplied to test getter fallbacks.
# Returns: object<string, any> (partial algorithm component), with name,
#   bom-ref, and nested cryptoProperties; primitive is "signature", with no type field.
component(algorithm_name, algorithm_family, algorithm_oid) := {
	"name": algorithm_name,
	"bom-ref": "signature-test",
	"cryptoProperties": {
		"assetType": "algorithm",
		"oid": algorithm_oid,
		"algorithmProperties": {"primitive": "signature", "algorithmFamily": algorithm_family},
	},
} if {
	is_string(algorithm_name)
	test_types.is_json_value(algorithm_family)
	test_types.is_json_value(algorithm_oid)
}

# Args:
#   test_component: object with cryptoProperties.algorithmProperties: object.
#   algorithm_properties: object<string, any>; overrides may contain malformed values.
# Returns: object<string, any> (component with merged algorithm properties).
with_properties(test_component, algorithm_properties) := object.union(test_component, {"cryptoProperties": object.union(test_component.cryptoProperties, {"algorithmProperties": object.union(test_component.cryptoProperties.algorithmProperties, algorithm_properties)})}) if {
	test_types.is_string_keyed_object(test_component)
	test_types.is_string_keyed_object(test_component.cryptoProperties)
	test_types.is_string_keyed_object(test_component.cryptoProperties.algorithmProperties)
	test_types.is_string_keyed_object(algorithm_properties)
}

# Exercise every agreed signature scheme through both family and name recognition,
# independently of parameter assessment.
test_every_table_scheme_is_agreed_by_family_and_name if {
	every algorithm_name in ["RSASSA-PSS", "KCDSA", "Schnorr", "DSA", "EC-KCDSA", "ECDSA", "EC-GDSA", "EC-Schnorr", "Deterministic ECDSA", "EdDSA", "ML-DSA", "XMSS", "LMS", "SLH-DSA", "RSASSA-PKCS1-v1_5"] {
		component_identified_by_name := component(algorithm_name, "", "")
		component_identified_by_family := component("custom", algorithm_name, "")
		get_signature_scheme(component_identified_by_name) == algorithm_name
		get_signature_scheme(component_identified_by_family) == algorithm_name
		findings == set() with input as {"components": [component_identified_by_name, component_identified_by_family]}
	}
}

# Registered signature OIDs must win over contradictory unagreed names and families.
test_signature_oids_override_family_and_name if {
	every test_case in [
		["1.2.840.113549.1.1.10", "RSASSA-PSS"],
		["1.2.840.113549.1.1.11", "RSASSA-PKCS1-v1_5"],
		["1.2.840.10040.4.3", "DSA"],
		["1.2.840.10045.4.3.2", "ECDSA"],
		["1.3.101.112", "EdDSA"],
		["1.3.101.113", "EdDSA"],
		["1.2.840.113549.1.9.16.3.17", "LMS"],
		["2.16.840.1.101.3.4.3.18", "ML-DSA"],
		["2.16.840.1.101.3.4.3.29", "SLH-DSA"],
	] {
		test_component := component("Falcon", "SM2", test_case[0])
		get_signature_scheme(test_component) == test_case[1]
		findings == set() with input as {"components": [test_component]}
	}
}

# A recognized family remains authoritative when OID evidence is unusable, even if the
# name describes an agreed scheme.
test_family_overrides_name_when_oid_is_unknown_or_malformed if {
	every algorithm_oid in ["", "1.2.3.4.5", "not-an-oid", null, 7, [], {}] {
		test_component := component("ML-DSA", "Falcon", algorithm_oid)
		get_signature_scheme(test_component) == "Falcon"
		actual_findings := findings with input as {"components": [test_component]}
		count(actual_findings) == 1
		some finding in actual_findings
		finding.ruleId == "ECCG-DG-001"
		finding.severity == "critical"
		finding.schemeIdentifier == "Falcon"
	}
}

# Generic key families and unknown family values cannot determine a signature scheme, so
# the name remains usable evidence.
test_generic_or_unrecognized_family_allows_name_fallback if {
	every algorithm_family in ["", "RSA", "custom", null, 7, [], {}] {
		test_component := component("RSA-PSS", algorithm_family, "1.2.840.113549.1.1.1")
		get_signature_scheme(test_component) == "RSASSA-PSS"
		findings == set() with input as {"components": [test_component]}
	}
}

# Normalization must preserve scheme detection and the finding’s identifier metadata.
test_normalization_and_metadata if {
	test_component := with_properties(component(" custom ", " FaLcOn ", " \t1.3.101.112\n"), {"primitive": " Signature "})
	get_signature_scheme(test_component) == "EdDSA"
	unrecognized_signature_component := component(" CustomSig ", " CUSTOM ", " 1.2.3.4 ")
	actual_findings := findings with input as {"components": [unrecognized_signature_component]}
	count(actual_findings) == 1
	some finding in actual_findings
	finding.schemeIdentifier == "custom"
	finding.oid == "1.2.3.4"
	finding.algorithmFamily == "custom"
	finding.bomRef == "signature-test"
	finding.component == "customsig"
}

# Supported aliases and parameterized labels must identify their signature construction
# without treating arbitrary fragments as agreement.
test_aliases_and_parameterized_names if {
	every test_case in [
		[" PkCs#1v1.5 ", "RSASSA-PKCS1-v1_5"],
		["RSA-PKCS1-1.5-3072", "RSASSA-PKCS1-v1_5"],
		["SHA256withRSA", "RSASSA-PKCS1-v1_5"],
		["SHA256withRSAandMGF1", "RSASSA-PSS"],
		["SHA512withRSA/PSS", "RSASSA-PSS"],
		["RSA-PSS-SHA-256-MGF1-3072", "RSASSA-PSS"],
		["RSA-PSS-SHA256-MGF1-MAX-3072", "RSASSA-PSS"],
		["ECDSA / EC-DSA", "ECDSA"],
		["SHA384withECDSA", "ECDSA"],
		["ECDSA-P256", "ECDSA"],
		["SHA256withDSA", "DSA"],
		["RFC6979-ECDSA", "Deterministic ECDSA"],
		["Ed25519ph", "EdDSA"],
		["Ed448", "EdDSA"],
		["ML_DSA_65", "ML-DSA"],
		["SLH-DSA-SHAKE-256s", "SLH-DSA"],
		["XMSS-SHA2_10_256", "XMSS"],
		["XMSSMT-SHA2_20/2_256", "XMSS"],
		["HSS/LMS", "LMS"],
		["LMS_SHA256_M32_H10", "LMS"],
	] {
		test_component := component(test_case[0], "", "")
		get_signature_scheme(test_component) == test_case[1]
		findings == set() with input as {"components": [test_component]}
	}
}

# Declared signature usage remains critical when no agreed construction can be
# established.
test_unknown_generic_and_misleading_signatures_are_rejected if {
	every algorithm_name in ["", "CustomSig", "RSA", "RSASSA", "EC", "Falcon", "SM2", "Dilithium", "SPHINCS+", "not-ECDSA", "ECDSA-wrapper", "DSAnything", "ML-DSA-wrapper", "ML-DSA-650", "SLH-DSA-SHAKE-256s-custom", "RSA-PKCS1-1.50", "Ed25519+ML-DSA"] {
		actual_findings := findings with input as {"components": [component(algorithm_name, "", "")]}
		count(actual_findings) == 1
		some finding in actual_findings
		finding.ruleId == "ECCG-DG-001"
		finding.severity == "critical"
	}
}

# A signature-looking identifier must not override an explicitly unrelated primitive.
test_explicit_other_primitives_are_excluded if {
	every primitive_type in ["pke", "kem", "key-agree", "hash", "mac", "block-cipher"] {
		test_component := with_properties(component("Falcon", "EdDSA", "1.3.101.112"), {"primitive": primitive_type})
		not is_digital_signature_component(test_component)
		findings == set() with input as {"components": [test_component]}
	}
}

# Key material and ordinary software components must not be assessed as signature
# operations.
test_key_material_and_non_crypto_components_are_excluded if {
	every asset_type in ["related-crypto-material", "certificate", "protocol", "", null] {
		base_component := component("Falcon", "", "")
		test_component := object.union(base_component, {"cryptoProperties": object.union(base_component.cryptoProperties, {"assetType": asset_type})})
		not is_digital_signature_component(test_component)
		findings == set() with input as {"components": [test_component]}
	}
	findings == set() with input as {"components": [{"name": "Falcon"}, {}, null]}
}

# Explicit signature identifiers can establish operation context when the primitive
# field is missing.
test_missing_primitive_can_be_inferred_from_each_identifier if {
	every base_component in [component("", "", "1.3.101.112"), component("", "ECDSA", ""), component("KCDSA", "", "")] {
		test_component := with_properties(base_component, {"primitive": ""})
		is_digital_signature_component(test_component)
		findings == set() with input as {"components": [test_component]}
	}
	unrecognized_signature_component := with_properties(component("CustomSig", "", ""), {"primitive": "", "cryptoFunctions": [" Sign "]})
	is_digital_signature_component(unrecognized_signature_component)
	actual_findings := findings with input as {"components": [unrecognized_signature_component]}
	count(actual_findings) == 1
}

# Generic key identifiers and encryption/KEM context must prevent unsupported signature
# inference.
test_bare_keys_and_contradictory_encryption_context_are_not_inferred if {
	every base_component in [
		component("RSA", "RSA", "1.2.840.113549.1.1.1"),
		component("EC", "EC", "1.2.840.10045.2.1"),
		component("ECDSA", "ECDH", ""),
		component("ECDSA", "", "1.3.101.110"),
		component("RSA-PKCS1-1.5", "RSAES-PKCS1", ""),
		component("ML-DSA", "ML-KEM", ""),
		component("ML-DSA", "", "2.16.840.1.101.3.4.4.2"),
	] {
		test_component := with_properties(base_component, {"primitive": ""})
		not is_digital_signature_component(test_component)
	}
	every crypto_function in ["encrypt", "decrypt", "encapsulate", "decapsulate"] {
		test_component := with_properties(component("RSA-PKCS1-1.5", "", ""), {"primitive": "", "cryptoFunctions": [crypto_function]})
		not is_digital_signature_component(test_component)
	}
	test_component := with_properties(component("custom", "RSAES-OAEP", "1.3.101.112"), {"primitive": ""})
	is_digital_signature_component(test_component)
	get_signature_scheme(test_component) == "EdDSA"
}

# Signature rejection must affect the section result and survive aggregation with its
# location metadata.
test_compliance_and_aggregate_integration if {
	input_cbom := {"components": [component("CustomSig", "", "")]}
	not compliant with input as input_cbom
	aggregate_findings := all_findings with input as input_cbom
	signature_findings := [finding | some finding in aggregate_findings; finding.ruleId == "ECCG-DG-001"]
	count(signature_findings) == 1
	signature_findings[0].section == "Asymmetric Constructions"
	signature_findings[0].subsection == "Digital Signature Schemes"
	signature_findings[0].schemeIdentifier == "customsig"
	compliant with input as {"components": [component("EdDSA", "", "")]}
	compliant with input as {"components": []}
}
