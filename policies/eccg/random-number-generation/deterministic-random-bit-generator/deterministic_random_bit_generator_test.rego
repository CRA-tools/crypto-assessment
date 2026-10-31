package cbom.eccg.random_number_generation.deterministic_random_bit_generator_test

import data.cbom.eccg.classifying_helpers.is_drbg_primitive
import data.cbom.eccg.findings as all_findings
import data.cbom.eccg.oid_constants.NO_OID
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.findings
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.AGREED_DRBG_SCHEMES
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.get_drbg_scheme_or_empty as scheme

component(name, family, oid) := {
	"name": name,
	"bom-ref": "drbg-test",
	"cryptoProperties": {
		"assetType": "algorithm",
		"oid": oid,
		"algorithmProperties": {"primitive": "drbg", "algorithmFamily": family},
	},
}

with_properties(asset, properties) := object.union(asset, {"cryptoProperties": object.union(asset.cryptoProperties, {"algorithmProperties": object.union(asset.cryptoProperties.algorithmProperties, properties)})})

rule_ids(asset) := {finding.ruleId | some finding in result} if {
	result := findings with input as {"components": [asset]}
}

test_agreement_and_note_scope if {
	AGREED_DRBG_SCHEMES == {"HMAC_DRBG", "Hash_DRBG", "CTR_DRBG"}
	every name in ["HMAC_DRBG", "Hash_DRBG"] {
		every asset in [component(name, "", ""), component("custom", name, "")] {
			scheme(asset) == name
			rule_ids(asset) == {"ECCG-DRBG-002", "ECCG-DRBG-003", "ECCG-DRBG-004"}
		}
	}
	rule_ids(component("CTR_DRBG", "", "")) == {"ECCG-DRBG-002", "ECCG-DRBG-003", "ECCG-DRBG-004", "ECCG-DRBG-005"}
}

test_family_precedes_name_and_unrecognized_oid_allows_fallback if {
	every oid in ["", NO_OID, trim_space(NO_OID), "1.2.3.4.5", "invalid", null, 17, {}, []] {
		asset := component("HMAC_DRBG", " Dual_EC_DRBG ", oid)
		scheme(asset) == "Dual_EC_DRBG"
		rule_ids(asset) == {"ECCG-DRBG-001"}
		scheme(component("Hash_DRBG", "", oid)) == "Hash_DRBG"
		rule_ids(component("", "", oid)) == {"ECCG-DRBG-001"}
	}
	scheme(component("CTR_DRBG", " Hash_DRBG-SHA256 ", "")) == "Hash_DRBG"
	scheme(component("HMAC_DRBG", "DRBG", "")) == "HMAC_DRBG"
}

# Exercise the OID-first contract with a test-only map, without assigning a
# fictitious OID to a real generator in the production recognition constants.
test_registered_oid_precedes_family_and_name if {
	resolved := scheme(component("Hash_DRBG", "Dual_EC_DRBG", " 1.2.3.4.5 "))
		with data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.DRBG_OIDS as {"CTR_DRBG": "1.2.3.4.5"}
	resolved == "CTR_DRBG"
	ids := rule_ids(component("CTR_DRBG", "HMAC_DRBG", "1.2.3.4.5"))
		with data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.DRBG_OIDS as {"Dual_EC_DRBG": "1.2.3.4.5"}
	ids == {"ECCG-DRBG-001"}
}

test_case_separators_and_parameterized_names if {
	every case in [
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
		asset := component(case[0], "", "")
		scheme(asset) == case[1]
		not "ECCG-DRBG-001" in rule_ids(asset)
	}
}

test_unagreed_missing_and_misleading_identifiers_are_critical if {
	every name in ["", null, 17, [], {}, "DRBG", "Dual_EC_DRBG", "Dual_EC_DRBG-P256", "Fortuna", "Yarrow", "MT19937", "CustomRNG", "not-HMAC_DRBG", "Hash_DRBG-wrapper", "CTR_DRBG-AES-256-custom", "HMAC_DRBG-SHA256-extra", "Hash_DRBG-SHA224-256", "HMAC", "SHA256", "AES-CTR", "os.urandom", "secrets.token_bytes"] {
		asset := component(name, "", "")
		rule_ids(asset) == {"ECCG-DRBG-001"}
		result := findings with input as {"components": [asset]}
		count(result) == 1
		some finding in result
		finding.severity == "critical"
	}
}

test_building_block_oids_do_not_identify_a_drbg if {
	every oid in ["1.2.840.113549.2.9", "2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.1.42"] {
		rule_ids(component("", "", oid)) == {"ECCG-DRBG-001"}
		scheme(component("Hash_DRBG", "", oid)) == "Hash_DRBG"
	}
}

test_shared_primitive_helper_controls_scope if {
	every primitive in ["drbg", " DRBG "] {
		every asset_type in ["algorithm", "related-crypto-material"] {
			base := with_properties(component("HMAC_DRBG", "", ""), {"primitive": primitive})
			asset := object.union(base, {"cryptoProperties": object.union(base.cryptoProperties, {"assetType": asset_type})})
			is_drbg_primitive(asset)
			count(rule_ids(asset)) == 3
		}
	}
	every primitive in ["", null, 17, "hash", "mac", "block-cipher", "kdf", "signature", "kem", "key-agree"] {
		asset := with_properties(component("HMAC_DRBG", "HMAC_DRBG", ""), {"primitive": primitive})
		not is_drbg_primitive(asset)
		rule_ids(asset) == set()
	}
	every asset_type in ["certificate", "protocol", "", null] {
		base := component("HMAC_DRBG", "HMAC_DRBG", "")
		asset := object.union(base, {"cryptoProperties": object.union(base.cryptoProperties, {"assetType": asset_type})})
		rule_ids(asset) == set()
	}

	missing := findings with input as {"components": [{}, {"name": "HMAC_DRBG"}]}
	missing == set()
	empty := findings with input as {}
	empty == set()
}

test_parameter_size_does_not_prove_seed_entropy_or_cipher_key_size if {
	every parameter in ["128", "192", "256", "440", "AES-256", "SHA256", 256, null, {}, []] {
		asset := with_properties(component("CTR_DRBG", "", ""), {"parameterSetIdentifier": parameter})
		rule_ids(asset) == {"ECCG-DRBG-002", "ECCG-DRBG-003", "ECCG-DRBG-004", "ECCG-DRBG-005"}
	}
}

test_findings_include_notes_metadata_and_conditions if {
	asset := component("CTR_DRBG", "CTR_DRBG", "")
	result := findings with input as {"components": [asset]}
	notes_by_rule := {
		"ECCG-DRBG-002": "71-DRG-Seeding",
		"ECCG-DRBG-003": "72-Quantum-Threat",
		"ECCG-DRBG-004": "73-BacktrackingResistance",
		"ECCG-DRBG-005": "74-QuantumThreat",
	}
	every finding in result {
		finding.severity == "warning"
		finding.notes.title == notes_by_rule[finding.ruleId]
		finding.notes.text != "Note not found"
		finding.schemeIdentifier == "CTR_DRBG"
		finding.algorithmFamily == "ctr_drbg"
		finding.bomRef == "drbg-test"
	}
	by_rule := {finding.ruleId: finding.message | some finding in result}
	contains(by_rule["ECCG-DRBG-002"], "125 bits of min-entropy")
	contains(by_rule["ECCG-DRBG-003"], "Where resistance to quantum attacks is required")
	contains(by_rule["ECCG-DRBG-003"], "188 bits of min-entropy")
	contains(by_rule["ECCG-DRBG-004"], "Where perfect forward secrecy is required")
	contains(by_rule["ECCG-DRBG-005"], "at least 192 bits")
}

test_findings_are_included_in_main_policy if {
	result := all_findings with input as {"components": [component("Dual_EC_DRBG", "", "")]}
	some finding in result
	finding.ruleId == "ECCG-DRBG-001"
	finding.severity == "critical"
	finding.section == "Random Number Generation"
	finding.subsection == "Deterministic Random Bit Generator"
	finding.policyPath == "Random Number Generation / Deterministic Random Bit Generator"
}
