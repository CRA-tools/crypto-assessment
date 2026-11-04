package cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation_test

# Focused establishment/KEM regressions cover shared primitive selection, identifier
# precedence, and parameter recommendations. Invalid values are deliberate robustness
# cases and are separate from exported valid CBOM fixtures.

import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.findings
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.AGREED_KEY_ESTABLISHMENT_SCHEMES
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.get_key_establishment_scheme_or_empty as get_key_establishment_scheme
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.get_kem_parameter_size_or_empty as get_kem_parameter_size
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.is_key_establishment_component
import data.cbom.eccg.findings as all_findings
import data.cbom.eccg.test_type_helpers as test_types

# Args:
#   algorithm_name, algorithm_family: string.
#   algorithm_oid: any JSON value; malformed values test getter fallbacks.
# Returns: object<string, any> (partial algorithm component), with name,
#   bom-ref, and nested cryptoProperties; primitive is "kem", with no type field.
component(algorithm_name, algorithm_family, algorithm_oid) := {
	"name": algorithm_name,
	"bom-ref": "key-establishment-test",
	"cryptoProperties": {
		"assetType": "algorithm",
		"oid": algorithm_oid,
		"algorithmProperties": {"primitive": "kem", "algorithmFamily": algorithm_family},
	},
} if {
	is_string(algorithm_name)
	is_string(algorithm_family)
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

# Args:
#   test_component: object<string, any> (complete or partial component).
# Returns: set<string> of ECCG rule identifiers; may be empty.
# Locals:
#   actual_findings: set<object> of findings.
#   finding: object (one finding with a string ruleId).
rule_ids(test_component) := {finding.ruleId | some finding in actual_findings} if {
	test_types.is_string_keyed_object(test_component)
	actual_findings := findings with input as {"components": [test_component]}
	is_set(actual_findings)
	test_types.is_findings(actual_findings)
}

# Every agreed key-establishment scheme avoids rejection but retains the
# party-authentication advisory.
test_all_eight_schemes_are_agreed_and_require_authentication if {
	AGREED_KEY_ESTABLISHMENT_SCHEMES == {"DH", "DLIES-KEM", "EC-DH", "ECIES-KEM", "X25519", "X448", "ML-KEM", "FrodoKEM"}
	every algorithm_name in ["DH", "DLIES-KEM", "EC-DH", "ECIES-KEM", "X25519", "X448", "ML-KEM", "FrodoKEM"] {
		every test_component in [component(algorithm_name, "", ""), component("custom", algorithm_name, "")] {
			get_key_establishment_scheme(test_component) == algorithm_name
			actual_rule_ids := rule_ids(test_component)
			"ECCG-KEE-002" in actual_rule_ids
			not "ECCG-KEE-001" in actual_rule_ids
		}
	}
}

# Registered establishment OIDs must select the scheme despite contradictory family and
# name labels.
test_oid_precedes_family_and_name if {
	every test_case in [
		["1.2.840.10046.2.1", "DH"],
		["1.2.840.113549.1.3.1", "DH"],
		["1.3.132.1.12", "EC-DH"],
		["1.3.101.110", "X25519"],
		["1.3.101.111", "X448"],
		["2.16.840.1.101.3.4.4.2", "ML-KEM"],
	] {
		test_component := component("FrodoKEM-640", "Kyber", test_case[0])
		get_key_establishment_scheme(test_component) == test_case[1]
		rule_ids(test_component) == {"ECCG-KEE-002"}
	}
	test_component := component("ML-KEM-768", "DH", "1.3.132.1.13")
	get_key_establishment_scheme(test_component) == "ECMQV"
	rule_ids(test_component) == {"ECCG-KEE-001"}
}

# A recognized establishment family overrides the name when the OID is unknown.
test_family_precedes_name_and_unknown_oids_allow_fallback if {
	every algorithm_oid in ["", "1.2.3.4.5", "invalid", null, 7, [], {}] {
		test_component := component("ML-KEM-768", " KyBeR ", algorithm_oid)
		get_key_establishment_scheme(test_component) == "Kyber"
		rule_ids(test_component) == {"ECCG-KEE-001"}
	}
	test_component := component("unrecognized", " ML_KEM_768 ", "")
	get_key_establishment_scheme(test_component) == "ML-KEM"
	rule_ids(test_component) == {"ECCG-KEE-002"}
}

# Supported scheme names must remain usable when a generic family provides insufficient
# scheme detail.
test_names_and_generic_families if {
	every test_case in [
		["FFDH-ffdhe3072", "", "DH"],
		["FFDHE3072", "", "DH"],
		["DLIES-KEM-ffdhe3072", "DLIES", "DLIES-KEM"],
		["ECDH-nist/P-256", "EC", "EC-DH"],
		["ECDHE-brainpoolP256r1", "", "EC-DH"],
		["ECIES-KEM-nist/P-256", "ECIES", "ECIES-KEM"],
		[" x25519 ", "", "X25519"],
		["X448", "", "X448"],
		["ML_KEM_1024", "", "ML-KEM"],
		["FrodoKEM-976-SHAKE", "", "FrodoKEM"],
	] {
		test_component := component(test_case[0], test_case[1], "")
		get_key_establishment_scheme(test_component) == test_case[2]
		rule_ids(test_component) == {"ECCG-KEE-002"}
	}
}

# Unknown schemes, composites, and misleading names must not acquire agreement from a
# partial match.
test_unknown_and_misleading_schemes_are_rejected if {
	every algorithm_name in ["", "CustomKEM", "J-PAKE", "Kyber-768", "CRYSTALS-Kyber", "RSA-KEM", "ECIES", "DLIES", "not-ECDH", "DH-wrapper", "ML-KEM-768-extra", "X25519MLKEM768", "FrodoKEM-976-custom"] {
		test_component := component(algorithm_name, "", "")
		rule_ids(test_component) == {"ECCG-KEE-001"}
		actual_findings := findings with input as {"components": [test_component]}
		count(actual_findings) == 1
		some finding in actual_findings
		finding.severity == "critical"
	}
}

# Establishment-looking text is insufficient when the primitive or asset category is
# unrelated.
test_other_primitives_and_unrelated_assets_are_excluded if {
	every primitive_type in ["signature", "pke", "hash", "mac", "kdf", "block-cipher"] {
		test_component := with_properties(component("ML-KEM", "ML-KEM", "2.16.840.1.101.3.4.4.2"), {"primitive": primitive_type})
		not is_key_establishment_component(test_component)
		rule_ids(test_component) == set()
	}
	every asset_type in ["certificate", "protocol", "", null] {
		base_component := component("ML-KEM", "ML-KEM", "")
		test_component := object.union(base_component, {"cryptoProperties": object.union(base_component.cryptoProperties, {"assetType": asset_type})})
		rule_ids(test_component) == set()
	}
}

# Pin the shared classifiers’ accepted asset types for explicit kem and key-agree
# primitives.
test_declared_primitives_accept_algorithms_and_related_crypto_material if {
	every primitive_type in ["kem", "key-agree", " KEM ", " Key-Agree "] {
		every asset_type in ["algorithm", "related-crypto-material"] {
			base_component := with_properties(component("ML-KEM-768", "", ""), {"primitive": primitive_type})
			test_component := object.union(base_component, {"cryptoProperties": object.union(base_component.cryptoProperties, {"assetType": asset_type})})
			is_key_establishment_component(test_component)
			rule_ids(test_component) == {"ECCG-KEE-002"}
		}
	}
}

# This section requires an explicit kem or key-agree primitive; names and crypto
# functions cannot replace it.
test_missing_primitive_is_not_inferred_from_identifiers_or_functions if {
	every base_component in [component("", "", "1.3.101.110"), component("", "EC-DH", ""), component("ML-KEM-768", "", "")] {
		test_component := with_properties(base_component, {"primitive": ""})
		not is_key_establishment_component(test_component)
		rule_ids(test_component) == set()
	}
	component_without_primitive := with_properties(component("custom", "", ""), {"primitive": "", "cryptoFunctions": " Encapsulate "})
	rule_ids(component_without_primitive) == set()
	every base_component in [
		component("EC", "EC", "1.2.840.10045.2.1"),
		component("ML-KEM-768", "ECDSA", ""),
		component("ML-KEM-768", "", "1.3.101.112"),
		component("ML-KEM-768", "", "1.2.840.113549.1.1.7"),
		component("HKDF", "HKDF", ""),
	] {
		test_component := with_properties(base_component, {"primitive": "", "cryptoFunctions": ["keyderive"]})
		rule_ids(test_component) == set()
	}
	every crypto_function in ["sign", "verify", "encrypt", "decrypt"] {
		test_component := with_properties(component("ML-KEM-768", "", ""), {"primitive": "", "cryptoFunctions": [crypto_function]})
		rule_ids(test_component) == set()
	}
}

# The parameter warning distinguishes ML-KEM-512 or unknown sizes from recommended 768
# and 1024 sets.
test_ml_kem_parameter_recommendation if {
	every parameter_set_identifier in ["768", "1024", " ML-KEM-768 ", "ml_kem_1024"] {
		test_component := with_properties(component("ML-KEM", "", ""), {"parameterSetIdentifier": parameter_set_identifier})
		rule_ids(test_component) == {"ECCG-KEE-002"}
	}
	every parameter_set_identifier in [512, 768, 1024, "512", "ML-KEM-512", "999", "", "malformed", "-768", "7.68", "ML-KEM-7.68", null, {}, [], true, -1, 768.5] {
		test_component := with_properties(component("ML-KEM", "", ""), {"parameterSetIdentifier": parameter_set_identifier})
		rule_ids(test_component) == {"ECCG-KEE-002", "ECCG-KEE-003"}
	}
}

# The parameter warning distinguishes FrodoKEM-640 or unknown sizes from recommended 976
# and 1344 sets.
test_frodokem_parameter_recommendation if {
	every parameter_set_identifier in ["976", "1344", "FrodoKEM-976-AES", "FrodoKEM-1344-SHAKE"] {
		test_component := with_properties(component("FrodoKEM", "", ""), {"parameterSetIdentifier": parameter_set_identifier})
		rule_ids(test_component) == {"ECCG-KEE-002"}
	}
	every parameter_set_identifier in [640, 976, 1344, "640", "FrodoKEM-640-AES", "ML-KEM-1024", "", "invalid", "-976", "9.76", "FrodoKEM-9.76", null, {}, [], true] {
		test_component := with_properties(component("FrodoKEM", "", ""), {"parameterSetIdentifier": parameter_set_identifier})
		rule_ids(test_component) == {"ECCG-KEE-002", "ECCG-KEE-004"}
	}
}

# An OID naming a concrete parameter set must override conflicting parameter and name
# metadata.
test_parameter_oid_overrides_conflicting_fields_and_names if {
	ml_kem_512_oid_component := with_properties(component("ML-KEM-1024", "FrodoKEM", " \t2.16.840.1.101.3.4.4.1\n"), {"parameterSetIdentifier": "768"})
	get_kem_parameter_size(ml_kem_512_oid_component) == 512
	rule_ids(ml_kem_512_oid_component) == {"ECCG-KEE-002", "ECCG-KEE-003"}
	ml_kem_1024_oid_component := component("FrodoKEM-640", "Kyber", "2.16.840.1.101.3.4.4.3")
	get_kem_parameter_size(ml_kem_1024_oid_component) == 1024
	rule_ids(ml_kem_1024_oid_component) == {"ECCG-KEE-002"}
}

# Malformed nonempty or lower parameter sets must remain visible rather than being
# replaced by a larger size in the name.
test_explicit_invalid_or_lower_parameters_are_not_hidden_by_names if {
	every parameter_set_identifier in ["bad", "FrodoKEM-976", "512"] {
		test_component := with_properties(component("ML-KEM-768", "", ""), {"parameterSetIdentifier": parameter_set_identifier})
		rule_ids(test_component) == {"ECCG-KEE-002", "ECCG-KEE-003"}
	}
	# The shared getter treats blank and non-string fields as absent.
	every parameter_set_identifier in ["", " \t ", null, {}, [], true, 512] {
		test_component := with_properties(component("ML-KEM-768", "", ""), {"parameterSetIdentifier": parameter_set_identifier})
		get_kem_parameter_size(test_component) == 768
		rule_ids(test_component) == {"ECCG-KEE-002"}
	}
	test_component := with_properties(component("FrodoKEM-1344-AES", "", ""), {"parameterSetIdentifier": "640"})
	get_kem_parameter_size(test_component) == 640
	rule_ids(test_component) == {"ECCG-KEE-002", "ECCG-KEE-004"}
	component_with_conflicting_scheme_name := component("FrodoKEM-976", "ML-KEM", "")
	get_kem_parameter_size(component_with_conflicting_scheme_name) == ""
	rule_ids(component_with_conflicting_scheme_name) == {"ECCG-KEE-002", "ECCG-KEE-003"}
	component_with_lower_parameter_family := component("ML-KEM-1024", "ML-KEM-512", "")
	get_kem_parameter_size(component_with_lower_parameter_family) == 512
	rule_ids(component_with_lower_parameter_family) == {"ECCG-KEE-002", "ECCG-KEE-003"}
}

# Authentication and parameter advisories must carry the applicable note and the
# scheme/parameter evidence used in assessment.
test_findings_include_correct_notes_and_parameter_metadata if {
	every test_case in [
		{"asset": component("ML-KEM-512", "", ""), "rule": "ECCG-KEE-003", "note": "64-ML-KEMParameters", "size": 512},
		{"asset": component("FrodoKEM-640-SHAKE", "", ""), "rule": "ECCG-KEE-004", "note": "65-FrodoKEMParameters", "size": 640},
	] {
		actual_findings := findings with input as {"components": [test_case.asset]}
		every finding in actual_findings {
			finding.severity == "warning"
			finding.notes.title != "unknown"
			finding.bomRef == "key-establishment-test"
		}
		parameter_findings := [finding | some finding in actual_findings; finding.ruleId == test_case.rule]
		count(parameter_findings) == 1
		parameter_findings[0].notes.title == test_case.note
		parameter_findings[0].parameterSize == test_case.size
		some authentication_finding in actual_findings
		authentication_finding.ruleId == "ECCG-KEE-002"
		authentication_finding.notes.title == "60-KE-Auth"
	}
}

# The main result must retain both advisory types exactly once for the same
# establishment asset.
test_aggregate_includes_parameter_and_authentication_findings_once if {
	aggregate_findings := all_findings with input as {"components": [component("ML-KEM-512", "", "")]}
	key_establishment_findings := [finding | some finding in aggregate_findings; startswith(finding.ruleId, "ECCG-KEE-")]
	count(key_establishment_findings) == 2
	{finding.ruleId | some finding in key_establishment_findings} == {"ECCG-KEE-002", "ECCG-KEE-003"}
	every finding in key_establishment_findings {
		finding.section == "Asymmetric Constructions"
		finding.subsection == "Key Establishment and Key Encapsulation Schemes"
	}
}
