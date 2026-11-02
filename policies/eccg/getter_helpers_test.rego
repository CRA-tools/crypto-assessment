package cbom.eccg.getter_helpers_test

# Getter contract tests use small records and intentionally invalid JSON values to
# isolate normalization, defined fallbacks, and CycloneDX field nesting. These records
# are not exported as schema-valid fixture documents.

import data.cbom.eccg.getter_helpers as getter_helpers
import data.cbom.eccg.getter_helpers.get_ec_curve_from_text_or_empty
import data.cbom.eccg.getter_helpers.get_ec_curve_or_empty
import data.cbom.eccg.test_type_helpers as test_types

# Exercise all scalar string getters with the same value, including malformed
# input, so normalization cannot turn a defined fallback into an undefined rule.
# Args:
#   field_value: any JSON value (string, number, boolean, null, array, or object).
# Returns: array<string> with 13 getter results in the order shown below.
# Locals:
#   test_component: object<string, any>; synthetic record containing field_value.
#   occurrence: object {location: any, additionalContext: any}.
#   getter_values: array<string>; getter_value: string after its guard succeeds.
string_getter_results(field_value) := getter_values if {
	test_types.is_json_value(field_value)
	test_component := {
		"name": field_value,
		"bom-ref": field_value,
		"additionalContext": field_value,
		"cryptoProperties": {
			"assetType": field_value,
			"oid": field_value,
			"relatedCryptoMaterialProperties": {"type": field_value},
			"algorithmProperties": {
				"ellipticCurve": field_value,
				"algorithmFamily": field_value,
				"primitive": field_value,
				"mode": field_value,
				"parameterSetIdentifier": field_value,
			},
		},
	}
	occurrence := {"location": field_value, "additionalContext": field_value}
	getter_values := [
		getter_helpers.get_component_name_or_empty(test_component),
		getter_helpers.get_component_bom_ref_or_empty(test_component),
		getter_helpers.get_component_additional_context_or_empty(test_component),
		getter_helpers.get_related_crypto_material_type_or_empty(test_component),
		getter_helpers.get_component_asset_type_or_empty(test_component),
		getter_helpers.get_component_oid_or_empty(test_component),
		getter_helpers.get_component_elliptic_curve_or_empty(test_component),
		getter_helpers.get_component_algorithm_family_or_empty(test_component),
		getter_helpers.get_component_primitive_or_empty(test_component),
		getter_helpers.get_component_mode_or_empty(test_component),
		getter_helpers.get_component_parameter_set_identifier_or_empty(test_component),
		getter_helpers.get_component_occurrence_location_or_empty(occurrence),
		getter_helpers.get_component_occurrence_additional_context_or_empty(occurrence),
	]
	every getter_value in getter_values {
		is_string(getter_value)
	}
}

# Read related material under cryptoProperties. A malformed flattened field must neither
# supply missing data nor override the nested value.
test_related_material_properties_follow_cyclonedx_nesting if {
	test_component := {
		"type": "cryptographic-asset",
		"name": "private key",
		"cryptoProperties": {
			"assetType": "related-crypto-material",
			"relatedCryptoMaterialProperties": {"type": "private-key", "size": 2048},
		},
	}
	getter_helpers.get_related_crypto_material_type_or_empty(test_component) == "private-key"
	getter_helpers.get_related_crypto_material_size_or_negative_one(test_component) == 2048
	# A flattened field is malformed CycloneDX and must not replace nested data.
	flattened_material_fields := {"relatedCryptoMaterialProperties": {"type": "public-key", "size": 1024}}
	getter_helpers.get_related_crypto_material_type_or_empty(flattened_material_fields) == ""
	getter_helpers.get_related_crypto_material_type_or_empty(object.union(test_component, flattened_material_fields)) == "private-key"
}

# Algorithm identifiers are normalized, while references, paths, and context preserve
# case-sensitive text.
test_string_getters_lowercase_algorithms_and_preserve_case_sensitive_text if {
	string_getter_results("\u00a0\t Mixed Case/Value-01 \r\n") == [
		"mixed case/value-01", "Mixed Case/Value-01", "Mixed Case/Value-01",
		"mixed case/value-01", "mixed case/value-01", "Mixed Case/Value-01",
		"mixed case/value-01", "mixed case/value-01", "mixed case/value-01",
		"mixed case/value-01", "mixed case/value-01",
		"Mixed Case/Value-01", "Mixed Case/Value-01",
	]
}

# Whitespace and wrong JSON types must return defined empty fallbacks rather than
# breaking downstream policy evaluation.
test_string_getters_return_empty_for_blank_or_non_string_values if {
	every blank_or_non_string_value in ["", " \t\r\n\u00a0", null, true, 256, [], {}, ["RSA"]] {
		getter_values := string_getter_results(blank_or_non_string_value)
		count(getter_values) == 13
		every getter_value in getter_values {
			getter_value == ""
		}
	}
	getter_helpers.get_component_name_or_empty({}) == ""
	getter_helpers.get_component_asset_type_or_empty({}) == ""
	getter_helpers.get_component_asset_type_or_empty({"cryptoProperties": null}) == ""
}

# Normalize function arrays and supported legacy strings while filtering invalid
# entries.
test_crypto_functions_getter_normalizes_arrays_and_legacy_strings if {
	every test_case in [
		{"value": [" SIGN ", "VeRiFy", "\t", null, 7, {}, []], "expected": ["sign", "verify"]},
		{"value": [" EnCrYpT ", " DeCrYpT "], "expected": ["encrypt", "decrypt"]},
		{"value": " DeCrYpT ", "expected": ["decrypt"]},
	] {
		test_component := ec_component("RSA", {"cryptoFunctions": test_case.value})
		getter_helpers.get_component_crypto_function_or_empty(test_component) == test_case.expected
	}
	every invalid_crypto_functions in ["", " \t\n", null, true, 12, [], {}, [null, 12, " "]] {
		getter_helpers.get_component_crypto_function_or_empty(ec_component("RSA", {"cryptoFunctions": invalid_crypto_functions})) == []
	}
	getter_helpers.get_component_crypto_function_or_empty({}) == []
}

# Sign/verify classification must consume the getter’s normalized output consistently.
test_signature_classifiers_consume_normalized_crypto_functions if {
	every crypto_functions in [[" SIGN ", " VERIFY "], " SiGn "] {
		test_component := ec_component("RSA", {"cryptoFunctions": crypto_functions})
		data.cbom.eccg.classifying_helpers.is_sign_crypto_function(test_component)
	}
	test_component := ec_component("RSA", {"cryptoFunctions": [" SIGN ", " VERIFY "]})
	data.cbom.eccg.classifying_helpers.is_verify_crypto_function(test_component)
	not data.cbom.eccg.classifying_helpers.is_sign_crypto_function(ec_component("RSA", {"cryptoFunctions": []}))
}

# Numeric parameter strings may contain surrounding whitespace; malformed strings and
# numeric JSON values retain the getter’s fallback.
test_padded_parameter_set_can_be_converted_to_number if {
	test_component := ec_component("RSA", {"parameterSetIdentifier": " \t3072\n"})
	getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one(test_component) == 3072
	every invalid_parameter_set_identifier in [" \t", " 30 72 ", " nist/P-256 ", null, 3072] {
		getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one(ec_component("RSA", {"parameterSetIdentifier": invalid_parameter_set_identifier})) == -1
	}
}

# Building combined identifier text must omit absent fields and preserve parameter-set
# precedence during curve extraction.
test_algorithm_identifier_text_joins_only_present_fields if {
	test_component := ec_component(" ECDH ", {"primitive": " KEY-AGREE ", "ellipticCurve": " NIST P-256 "})
	getter_helpers.get_component_algorithm_identifier_text(test_component) == "ecdh key-agree nist p-256"
	getter_helpers.get_component_algorithm_identifier_text({}) == ""
	get_ec_curve_or_empty(ec_component("ECDH-P-521", {"ellipticCurve": " \t ", "parameterSetIdentifier": " nist/P-256 "})) == "nist p-256"
}

# Shared normalization must remain compatible with the family constants used by
# block-cipher, MAC, KDF, and password helpers.
test_lowercase_getter_convention_matches_policy_family_constants if {
	every algorithm_family in ["AES", "aes", " \taEs\n"] {
		test_component := ec_component("unknown", {"primitive": " BLOCK-CIPHER ", "algorithmFamily": algorithm_family, "mode": " CBC "})
		data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.is_aes_component(test_component)
		data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_cbc_scheme(test_component)
	}
	hmac_component := ec_component("unknown", {"primitive": " MAC ", "algorithmFamily": " hMaC "})
	data.cbom.eccg.symmetric_constructions.macs.helpers.is_hmac_scheme(hmac_component)
	pbkdf2_component := ec_component("unknown", {"primitive": " KDF ", "algorithmFamily": " pBkDf2 "})
	data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_pbkdf2_scheme(pbkdf2_component)
	data.cbom.eccg.symmetric_constructions.password_protection.helpers.is_pbkdf2_scheme(pbkdf2_component)
	argon2_component := ec_component("unknown", {"primitive": " KDF ", "algorithmFamily": " aRgOn2 "})
	data.cbom.eccg.symmetric_constructions.password_protection.helpers.is_argon2id_scheme(argon2_component)
}

# Dependency joins trim whitespace but retain bom-ref case sensitivity; invalid or
# unresolved references must not resolve to assets.
test_dependency_getters_trim_references_consistently if {
	key_material_component := {"bom-ref": " Key-1 ", "cryptoProperties": {"assetType": " RELATED-CRYPTO-MATERIAL "}}
	algorithm_component := object.union(ec_component(" RSA ", {}), {"bom-ref": " RSA-1\t"})
	key_dependency := {"ref": "\tKey-1", "dependsOn": [" RSA-1 ", "", " \t ", null, 7]}
	input_cbom := {"components": [key_material_component, algorithm_component, {"bom-ref": ""}], "dependencies": [key_dependency]}
	getter_helpers.get_component_dependency(key_material_component) == key_dependency with input as input_cbom
	getter_helpers.get_component_dependency_refs_or_empty(key_material_component) == ["RSA-1"] with input as input_cbom
	getter_helpers.get_component_dependency_components_or_empty(key_material_component) == [algorithm_component] with input as input_cbom
	getter_helpers.get_related_algorithm_for_key_material_or_empty(key_material_component) == algorithm_component with input as input_cbom
	getter_helpers.get_component_by_bomref("\nRSA-1 ") == algorithm_component with input as input_cbom
	not getter_helpers.get_component_by_bomref("rsa-1") with input as input_cbom
	not getter_helpers.get_component_by_bomref(" \t ") with input as input_cbom
	not getter_helpers.get_component_by_bomref(null) with input as input_cbom
}

# Args:
#   algorithm_name: string.
#   algorithm_properties: object<string, any>; values may be malformed on purpose.
# Returns: object with name: string and cryptoProperties: object, containing
#   assetType: "algorithm" and the supplied algorithmProperties object.
#   This is a partial component, without type or bom-ref.
ec_component(algorithm_name, algorithm_properties) := {
	"name": algorithm_name,
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": algorithm_properties,
	},
} if {
	is_string(algorithm_name)
	test_types.is_string_keyed_object(algorithm_properties)
}

# Recognizable curve aliases inside algorithm text must resolve to the same canonical
# curve token.
test_ec_text_recognizes_curve_aliases_and_embedded_names if {
	every curve_text, expected_curve in {
		"ECDH-brainpool/brainpoolP256r1": "BrainpoolP256r1",
		"brainpool/brainpoolP384r1": "BrainpoolP384r1",
		"BRAINPOOLP512R1": "BrainpoolP512r1",
		"ECDH-anssi/FRP256v1": "FRP256v1",
		"ECDSA-P-256": "NIST P-256",
		"ECDH-P-384": "NIST P-384",
		"ECDSA-P-521": "NIST P-521",
		"NIST_p-256": "NIST P-256",
		"nist/P-384": "NIST P-384",
		"secp521r1": "NIST P-521",
		"secg/secp256r1": "NIST P-256",
		"secg/secp384r1": "NIST P-384",
		"x962/prime256v1": "NIST P-256",
		"ECDSA (P-256), SHA-256": "NIST P-256",
		"Curve25519": "Curve25519",
		"other/Curve448": "Curve448",
		"X25519": "X25519",
		"ECDH-X448": "X448",
		"Edwards25519": "Ed25519",
		"EdDSA-Edwards448": "Ed448",
		"other/Ed25519": "Ed25519",
		"Ed448": "Ed448",
	} {
		get_ec_curve_from_text_or_empty(curve_text) == lower(expected_curve)
	}
}

# Extraction must retain a recognized disallowed curve so the policy can reject it
# rather than report missing evidence.
test_ec_text_preserves_recognized_non_agreed_curves if {
	every curve_text, expected_curve in {
		"ECDH-secp256k1": "secp256k1",
		"ECDH-secp224r1": "secp224r1",
		"ECDSA-nist/P-192": "secp192r1",
		"ECDSA-P-224": "secp224r1",
		"ECDH-brainpoolP160r1": "BrainpoolP160r1",
		"ECDH-brainpoolP256t1": "BrainpoolP256t1",
		"EC-NIST B-283": "NIST B-283",
		"EC-NIST K-283": "NIST K-283",
		"EC-SM2": "SM2",
	} {
		get_ec_curve_from_text_or_empty(curve_text) == lower(expected_curve)
	}
}

# Token boundaries prevent a curve identifier from matching a longer, different
# identifier.
test_ec_text_rejects_partial_identifier_matches if {
	every curve_text in [
		"secp256r10", "notsecp256r1", "secp256r1suffix", "NIST-P-2560",
		"Curve255190", "X4480", "Ed255190", "Edwards4480", "SM20",
		"brainpoolP256r10", "notbrainpoolP256r1", "FRP256v10",
	] {
		get_ec_curve_from_text_or_empty(curve_text) == ""
	}
}

# Two distinct curves make the text ambiguous regardless of token ordering.
test_ec_text_rejects_ambiguous_curves_in_either_order if {
	every curve_text in [
		"ECDH-secp256k1-NIST-P-256", "ECDH-NIST-P-256-secp256k1",
		"ECDSA-P-256/P-384", "ECDSA-P-384/P-256",
		"ECDH-brainpoolP256t1-brainpoolP256r1",
		"EdDSA-Edwards25519-Edwards448", "X25519-X448",
	] {
		get_ec_curve_from_text_or_empty(curve_text) == ""
	}
}

# Repeated aliases for one curve should not be treated as evidence of conflicting
# curves.
test_ec_text_deduplicates_aliases_for_the_same_curve if {
	get_ec_curve_from_text_or_empty("ECDH-NIST-P-256-secp256r1-prime256v1") == "nist p-256"
	get_ec_curve_from_text_or_empty("EdDSA-Edwards25519-Ed25519") == "ed25519"
}

# Absent, malformed, and unrecognized text must leave curve extraction defined with an
# empty result.
test_ec_text_missing_or_invalid_input_returns_empty if {
	every curve_text in ["", "ECDH", "custom-curve", "256", null, 256, true, [], {}] {
		get_ec_curve_from_text_or_empty(curve_text) == ""
	}
}

# A recognized curve in parameterSetIdentifier has priority over the curve inferred from
# the name.
test_ec_curve_uses_parameter_set_before_name if {
	every parameter_set_identifier, expected_curve in {
		"nist/P-256": "NIST P-256",
		"ECDSA-P-384": "NIST P-384",
		"Edwards25519": "Ed25519",
		"secp224r1": "secp224r1",
		"brainpoolP256t1": "BrainpoolP256t1",
	} {
		test_component := ec_component("ECDH-P-521", {"parameterSetIdentifier": parameter_set_identifier})
		get_ec_curve_or_empty(test_component) == lower(expected_curve)
	}
}

# Explicit ellipticCurve metadata is authoritative over both parameter-set and name
# inference.
test_ec_curve_preserves_explicit_curve_precedence if {
	test_component := ec_component("ECDH-P-521", {"ellipticCurve": "secp256k1", "parameterSetIdentifier": "nist/P-256"})
	get_ec_curve_or_empty(test_component) == "secp256k1"
	component_with_ambiguous_parameter := ec_component("ECDH-P-521", {"ellipticCurve": "nist/P-256", "parameterSetIdentifier": "P-256/P-384"})
	get_ec_curve_or_empty(component_with_ambiguous_parameter) == "nist/p-256"
}

# CBOMkit emits the older curve field. Its value must undergo the same trimming
# and lowercasing as ellipticCurve before the curve policy assesses it.
test_legacy_curve_field_is_normalized if {
	every curve_value in ["secp256r1", " SECP256R1 ", "\tSeCp256R1\n"] {
		test_component := ec_component("ECDH", {"curve": curve_value})
		getter_helpers.get_component_elliptic_curve_or_empty(test_component) == "secp256r1"
		get_ec_curve_or_empty(test_component) == "secp256r1"
	}
}

# A nonempty registry field stays authoritative, including an unrecognized value;
# the legacy field must not hide evidence that the curve is outside the allowlist.
test_elliptic_curve_field_precedes_legacy_curve if {
	every curve_value in ["nist/P-256", "secg/secp256k1", "unknown"] {
		test_component := ec_component("ECDH", {"ellipticCurve": curve_value, "curve": "secp384r1"})
		getter_helpers.get_component_elliptic_curve_or_empty(test_component) == lower(curve_value)
		get_ec_curve_or_empty(test_component) == lower(curve_value)
	}
}

# An empty or malformed newer field supplies no curve evidence. A usable legacy
# value must remain available instead of causing a false missing-curve warning.
test_blank_or_malformed_elliptic_curve_field_uses_legacy_curve if {
	every invalid_curve_value in ["", " \t\r\n", null, 256, true, [], {}] {
		test_component := ec_component("ECDH", {"ellipticCurve": invalid_curve_value, "curve": " SECP256R1 "})
		getter_helpers.get_component_elliptic_curve_or_empty(test_component) == "secp256r1"
		get_ec_curve_or_empty(test_component) == "secp256r1"
	}
}

# Invalid legacy values retain the shared getter's empty fallback, leaving
# parameter-set and name extraction usable without coercing incorrect JSON types.
test_malformed_legacy_curve_field_allows_parameter_and_name_fallback if {
	every invalid_curve_value in ["", " \t\r\n", null, 256, true, [], {}] {
		test_component := ec_component("ECDH-P-521", {"curve": invalid_curve_value, "parameterSetIdentifier": "nist/P-256"})
		getter_helpers.get_component_elliptic_curve_or_empty(test_component) == ""
		get_ec_curve_or_empty(test_component) == "nist p-256"
		get_ec_curve_or_empty(ec_component("ECDH-P-256", {"curve": invalid_curve_value})) == "nist p-256"
		get_ec_curve_or_empty(ec_component("ECDH", {"curve": invalid_curve_value})) == ""
	}
}

# The legacy field is explicit curve metadata too: a smaller or disallowed curve
# there must not be replaced by an agreed parameter set or component-name token.
test_legacy_curve_field_precedes_parameter_and_name if {
	test_component := ec_component("ECDH-P-521", {"curve": "secp256k1", "parameterSetIdentifier": "nist/P-256"})
	get_ec_curve_or_empty(test_component) == "secp256k1"
}

# Combined identifier text must include the resolved curve once, using the same
# field precedence as direct curve assessment.
test_algorithm_identifier_text_includes_resolved_curve_field if {
	component_with_legacy_curve := ec_component("ECDH", {"primitive": "key-agree", "curve": " SECP256R1 "})
	getter_helpers.get_component_algorithm_identifier_text(component_with_legacy_curve) == "ecdh key-agree secp256r1"
	component_with_registry_curve := ec_component("ECDH", {"primitive": "key-agree", "ellipticCurve": "nist/P-384", "curve": "secp256r1"})
	getter_helpers.get_component_algorithm_identifier_text(component_with_registry_curve) == "ecdh key-agree nist/p-384"
}

# Ambiguous parameter evidence must not be replaced by a seemingly unambiguous curve in
# the name.
test_ec_curve_ambiguous_parameter_does_not_fall_back_to_name if {
	test_component := ec_component("ECDH-P-521", {"parameterSetIdentifier": "secp256k1/P-256"})
	get_ec_curve_or_empty(test_component) == ""
}

# A parameter that does not identify any curve leaves name-based extraction available.
test_ec_curve_non_curve_parameters_fall_back_to_name if {
	every parameter_set_identifier in ["", "256", "unknown", null, 256, true, [], {}] {
		test_component := ec_component("ECDH-P-256", {"parameterSetIdentifier": parameter_set_identifier})
		get_ec_curve_or_empty(test_component) == "nist p-256"
	}
	get_ec_curve_or_empty(ec_component("ECDH-P-256", {})) == "nist p-256"
	get_ec_curve_or_empty({}) == ""
}
