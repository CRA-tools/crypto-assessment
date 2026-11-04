package cbom.eccg.random_number_generation.deterministic_random_bit_generator_test

# Focused DRBG regressions cover scheme recognition, operational-note scope, and
# malformed input. Synthetic OID overrides test lookup behavior without claiming a real
# assigned generator OID.

import data.cbom.eccg.classifying_helpers.is_drbg_primitive
import data.cbom.eccg.findings as all_findings
import data.cbom.eccg.oid_constants.NO_OID
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.findings
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.AGREED_DRBG_SCHEMES
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.get_drbg_scheme_or_empty as get_drbg_scheme
import data.cbom.eccg.test_type_helpers as test_types

# Args:
#   algorithm_name, algorithm_oid: any JSON value; normally strings,
#       with malformed values supplied to test getter fallbacks.
#   algorithm_family: string.
# Returns: object<string, any> (partial algorithm component), with name,
#   bom-ref, and nested cryptoProperties; primitive is "drbg", with no type field.
component(algorithm_name, algorithm_family, algorithm_oid) := {
	"name": algorithm_name,
	"bom-ref": "drbg-test",
	"cryptoProperties": {
		"assetType": "algorithm",
		"oid": algorithm_oid,
		"algorithmProperties": {"primitive": "drbg", "algorithmFamily": algorithm_family},
	},
} if {
	test_types.is_json_value(algorithm_name)
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

# All three agreed DRBGs retain general operational notes; only CTR_DRBG receives the
# block-cipher-specific warning.
test_agreement_and_note_scope if {
	AGREED_DRBG_SCHEMES == {"HMAC_DRBG", "Hash_DRBG", "CTR_DRBG"}
	every algorithm_name in ["HMAC_DRBG", "Hash_DRBG"] {
		every test_component in [component(algorithm_name, "", ""), component("custom", algorithm_name, "")] {
			get_drbg_scheme(test_component) == algorithm_name
			rule_ids(test_component) == {"ECCG-DRBG-002", "ECCG-DRBG-003", "ECCG-DRBG-004"}
		}
	}
	rule_ids(component("CTR_DRBG", "", "")) == {"ECCG-DRBG-002", "ECCG-DRBG-003", "ECCG-DRBG-004", "ECCG-DRBG-005"}
}

# A recognized DRBG family overrides the name, while an unknown OID leaves that family
# usable.
test_family_precedes_name_and_unrecognized_oid_allows_fallback if {
	every algorithm_oid in ["", NO_OID, trim_space(NO_OID), "1.2.3.4.5", "invalid", null, 17, {}, []] {
		test_component := component("HMAC_DRBG", " Dual_EC_DRBG ", algorithm_oid)
		get_drbg_scheme(test_component) == "Dual_EC_DRBG"
		rule_ids(test_component) == {"ECCG-DRBG-001"}
		get_drbg_scheme(component("Hash_DRBG", "", algorithm_oid)) == "Hash_DRBG"
		rule_ids(component("", "", algorithm_oid)) == {"ECCG-DRBG-001"}
	}
	get_drbg_scheme(component("CTR_DRBG", " Hash_DRBG-SHA256 ", "")) == "Hash_DRBG"
	get_drbg_scheme(component("HMAC_DRBG", "DRBG", "")) == "HMAC_DRBG"
}

# Exercise the OID-first contract with a test-only map, without assigning a
# fictitious OID to a real generator in the production recognition constants.
# A synthetic table override tests future DRBG OID precedence without asserting that the
# synthetic OID is officially assigned.
test_registered_oid_precedes_family_and_name if {
	resolved_scheme := get_drbg_scheme(component("Hash_DRBG", "Dual_EC_DRBG", " 1.2.3.4.5 "))
		with data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.DRBG_OIDS as {"CTR_DRBG": "1.2.3.4.5"}
	resolved_scheme == "CTR_DRBG"
	actual_rule_ids := rule_ids(component("CTR_DRBG", "HMAC_DRBG", "1.2.3.4.5"))
		with data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.DRBG_OIDS as {"Dual_EC_DRBG": "1.2.3.4.5"}
	actual_rule_ids == {"ECCG-DRBG-001"}
}

# Supported case, separator, and parameter variations must preserve generator
# recognition.
test_case_separators_and_parameterized_names if {
	every test_case in [
		[" HmAc-DrBg ", "HMAC_DRBG"],
		["HMACDRBG", "HMAC_DRBG"],
		["HMAC_DRBG-SHA-256", "HMAC_DRBG"],
		["HMAC_DRBG-SHA512/256", "HMAC_DRBG"],
		["hash drbg", "Hash_DRBG"],
		["Hash_DRBG-SHA384", "Hash_DRBG"],
		["Hash_DRBG-SHA-512-224", "Hash_DRBG"],
		["CTR-DRBG", "CTR_DRBG"],
		["CTR_DRBG-AES-128", "CTR_DRBG"],
		["CTR_DRBG-AES192", "CTR_DRBG"],
		["CTR_DRBG-AES-256", "CTR_DRBG"],
		["CTR_DRBG-TDEA", "CTR_DRBG"],
	] {
		test_component := component(test_case[0], "", "")
		get_drbg_scheme(test_component) == test_case[1]
		not "ECCG-DRBG-001" in rule_ids(test_component)
	}
}

# Declared DRBG usage with unknown, missing, or misleading scheme evidence must produce
# a critical rejection.
test_unagreed_missing_and_misleading_identifiers_are_critical if {
	every algorithm_name in ["", null, 17, [], {}, "DRBG", "Dual_EC_DRBG", "Dual_EC_DRBG-P256", "Fortuna", "Yarrow", "MT19937", "CustomRNG", "not-HMAC_DRBG", "Hash_DRBG-wrapper", "CTR_DRBG-AES-256-custom", "HMAC_DRBG-SHA256-extra", "Hash_DRBG-SHA224-256", "HMAC", "SHA256", "AES-CTR", "os.urandom", "secrets.token_bytes"] {
		test_component := component(algorithm_name, "", "")
		rule_ids(test_component) == {"ECCG-DRBG-001"}
		actual_findings := findings with input as {"components": [test_component]}
		count(actual_findings) == 1
		some finding in actual_findings
		finding.severity == "critical"
	}
}

# Hash, MAC, and cipher OIDs describe building blocks and must not establish agreement
# for an unidentified generator.
test_building_block_oids_do_not_identify_a_drbg if {
	every algorithm_oid in ["1.2.840.113549.2.9", "2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.1.42"] {
		rule_ids(component("", "", algorithm_oid)) == {"ECCG-DRBG-001"}
		get_drbg_scheme(component("Hash_DRBG", "", algorithm_oid)) == "Hash_DRBG"
	}
}

# The shared DRBG classifier controls eligibility, including accepted asset types and
# exclusion of missing or unrelated primitives.
test_shared_primitive_helper_controls_scope if {
	every primitive_type in ["drbg", " DRBG "] {
		every asset_type in ["algorithm", "related-crypto-material"] {
			base_component := with_properties(component("HMAC_DRBG", "", ""), {"primitive": primitive_type})
			test_component := object.union(base_component, {"cryptoProperties": object.union(base_component.cryptoProperties, {"assetType": asset_type})})
			is_drbg_primitive(test_component)
			count(rule_ids(test_component)) == 3
		}
	}
	every primitive_type in ["", null, 17, "hash", "mac", "block-cipher", "kdf", "signature", "kem", "key-agree"] {
		test_component := with_properties(component("HMAC_DRBG", "HMAC_DRBG", ""), {"primitive": primitive_type})
		not is_drbg_primitive(test_component)
		rule_ids(test_component) == set()
	}
	every asset_type in ["certificate", "protocol", "", null] {
		base_component := component("HMAC_DRBG", "HMAC_DRBG", "")
		test_component := object.union(base_component, {"cryptoProperties": object.union(base_component.cryptoProperties, {"assetType": asset_type})})
		rule_ids(test_component) == set()
	}

	findings_for_missing_metadata := findings with input as {"components": [{}, {"name": "HMAC_DRBG"}]}
	findings_for_missing_metadata == set()
	findings_for_empty_input := findings with input as {}
	findings_for_empty_input == set()
}

# A reported generic parameter size cannot discharge seed-entropy or internal-cipher
# requirements that the CBOM does not establish.
test_parameter_size_does_not_prove_seed_entropy_or_cipher_key_size if {
	every parameter_set_identifier in ["128", "192", "256", "440", "AES-256", "SHA256", 256, null, {}, []] {
		test_component := with_properties(component("CTR_DRBG", "", ""), {"parameterSetIdentifier": parameter_set_identifier})
		rule_ids(test_component) == {"ECCG-DRBG-002", "ECCG-DRBG-003", "ECCG-DRBG-004", "ECCG-DRBG-005"}
	}
}

# Advisories must expose their note, identifier metadata, and applicable operational
# condition without claiming runtime verification.
test_findings_include_notes_metadata_and_conditions if {
	test_component := component("CTR_DRBG", "CTR_DRBG", "")
	actual_findings := findings with input as {"components": [test_component]}
	expected_note_titles_by_rule := {
		"ECCG-DRBG-002": "71-DRG-Seeding",
		"ECCG-DRBG-003": "72-Quantum-Threat",
		"ECCG-DRBG-004": "73-BacktrackingResistance",
		"ECCG-DRBG-005": "74-QuantumThreat",
	}
	every finding in actual_findings {
		finding.severity == "warning"
		finding.notes.title == expected_note_titles_by_rule[finding.ruleId]
		finding.notes.text != "Note not found"
		finding.schemeIdentifier == "CTR_DRBG"
		finding.algorithmFamily == "ctr_drbg"
		finding.bomRef == "drbg-test"
	}
	messages_by_rule := {finding.ruleId: finding.message | some finding in actual_findings}
	contains(messages_by_rule["ECCG-DRBG-002"], "125 bits of min-entropy")
	contains(messages_by_rule["ECCG-DRBG-003"], "Where resistance to quantum attacks is required")
	contains(messages_by_rule["ECCG-DRBG-003"], "188 bits of min-entropy")
	contains(messages_by_rule["ECCG-DRBG-004"], "Where perfect forward secrecy is required")
	contains(messages_by_rule["ECCG-DRBG-005"], "at least 192 bits")
}

# DRBG rejections and advisories must reach the main assessment with the proper section
# labels.
test_findings_are_included_in_main_policy if {
	aggregate_findings := all_findings with input as {"components": [component("Dual_EC_DRBG", "", "")]}
	some finding in aggregate_findings
	finding.ruleId == "ECCG-DRBG-001"
	finding.severity == "critical"
	finding.section == "Random Number Generation"
	finding.subsection == "Deterministic Random Bit Generator"
	finding.policyPath == "Random Number Generation / Deterministic Random Bit Generator"
}
