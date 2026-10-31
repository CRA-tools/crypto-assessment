package cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation_test

import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.findings
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.AGREED_KEY_ESTABLISHMENT_SCHEMES
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.get_key_establishment_scheme_or_empty as scheme
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.get_kem_parameter_size_or_empty as parameter_size
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.is_key_establishment_component
import data.cbom.eccg.findings as all_findings

component(name, family, oid) := {
	"name": name,
	"bom-ref": "key-establishment-test",
	"cryptoProperties": {
		"assetType": "algorithm",
		"oid": oid,
		"algorithmProperties": {"primitive": "kem", "algorithmFamily": family},
	},
}

with_properties(asset, properties) := object.union(asset, {"cryptoProperties": object.union(asset.cryptoProperties, {"algorithmProperties": object.union(asset.cryptoProperties.algorithmProperties, properties)})})

rule_ids(asset) := {finding.ruleId | some finding in result} if {
	result := findings with input as {"components": [asset]}
}

test_all_eight_schemes_are_agreed_and_require_authentication if {
	AGREED_KEY_ESTABLISHMENT_SCHEMES == {"DH", "DLIES-KEM", "EC-DH", "ECIES-KEM", "X25519", "X448", "ML-KEM", "FrodoKEM"}
	every name in ["DH", "DLIES-KEM", "EC-DH", "ECIES-KEM", "X25519", "X448", "ML-KEM", "FrodoKEM"] {
		every asset in [component(name, "", ""), component("custom", name, "")] {
			scheme(asset) == name
			ids := rule_ids(asset)
			"ECCG-KEE-002" in ids
			not "ECCG-KEE-001" in ids
		}
	}
}

test_oid_precedes_family_and_name if {
	every case in [
		["1.2.840.10046.2.1", "DH"],
		["1.2.840.113549.1.3.1", "DH"],
		["1.3.132.1.12", "EC-DH"],
		["1.3.101.110", "X25519"],
		["1.3.101.111", "X448"],
		["2.16.840.1.101.3.4.4.2", "ML-KEM"],
	] {
		asset := component("FrodoKEM-640", "Kyber", case[0])
		scheme(asset) == case[1]
		rule_ids(asset) == {"ECCG-KEE-002"}
	}
	asset := component("ML-KEM-768", "DH", "1.3.132.1.13")
	scheme(asset) == "ECMQV"
	rule_ids(asset) == {"ECCG-KEE-001"}
}

test_family_precedes_name_and_unknown_oids_allow_fallback if {
	every oid in ["", "1.2.3.4.5", "invalid", null, 7, [], {}] {
		asset := component("ML-KEM-768", " KyBeR ", oid)
		scheme(asset) == "Kyber"
		rule_ids(asset) == {"ECCG-KEE-001"}
	}
	asset := component("unrecognized", " ML_KEM_768 ", "")
	scheme(asset) == "ML-KEM"
	rule_ids(asset) == {"ECCG-KEE-002"}
}

test_names_and_generic_families if {
	every case in [
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
		asset := component(case[0], case[1], "")
		scheme(asset) == case[2]
		rule_ids(asset) == {"ECCG-KEE-002"}
	}
}

test_unknown_and_misleading_schemes_are_rejected if {
	every name in ["", "CustomKEM", "J-PAKE", "Kyber-768", "CRYSTALS-Kyber", "RSA-KEM", "ECIES", "DLIES", "not-ECDH", "DH-wrapper", "ML-KEM-768-extra", "X25519MLKEM768", "FrodoKEM-976-custom"] {
		asset := component(name, "", "")
		rule_ids(asset) == {"ECCG-KEE-001"}
		result := findings with input as {"components": [asset]}
		count(result) == 1
		some finding in result
		finding.severity == "critical"
	}
}

test_other_primitives_and_unrelated_assets_are_excluded if {
	every primitive in ["signature", "pke", "hash", "mac", "kdf", "block-cipher"] {
		asset := with_properties(component("ML-KEM", "ML-KEM", "2.16.840.1.101.3.4.4.2"), {"primitive": primitive})
		not is_key_establishment_component(asset)
		rule_ids(asset) == set()
	}
	every asset_type in ["certificate", "protocol", "", null] {
		base := component("ML-KEM", "ML-KEM", "")
		asset := object.union(base, {"cryptoProperties": object.union(base.cryptoProperties, {"assetType": asset_type})})
		rule_ids(asset) == set()
	}
}

test_declared_primitives_accept_algorithms_and_related_crypto_material if {
	every primitive in ["kem", "key-agree", " KEM ", " Key-Agree "] {
		every asset_type in ["algorithm", "related-crypto-material"] {
			base := with_properties(component("ML-KEM-768", "", ""), {"primitive": primitive})
			asset := object.union(base, {"cryptoProperties": object.union(base.cryptoProperties, {"assetType": asset_type})})
			is_key_establishment_component(asset)
			rule_ids(asset) == {"ECCG-KEE-002"}
		}
	}
}

test_missing_primitive_is_not_inferred_from_identifiers_or_functions if {
	every base in [component("", "", "1.3.101.110"), component("", "EC-DH", ""), component("ML-KEM-768", "", "")] {
		asset := with_properties(base, {"primitive": ""})
		not is_key_establishment_component(asset)
		rule_ids(asset) == set()
	}
	unknown := with_properties(component("custom", "", ""), {"primitive": "", "cryptoFunctions": " Encapsulate "})
	rule_ids(unknown) == set()
	every base in [
		component("EC", "EC", "1.2.840.10045.2.1"),
		component("ML-KEM-768", "ECDSA", ""),
		component("ML-KEM-768", "", "1.3.101.112"),
		component("ML-KEM-768", "", "1.2.840.113549.1.1.7"),
		component("HKDF", "HKDF", ""),
	] {
		asset := with_properties(base, {"primitive": "", "cryptoFunctions": ["keyderive"]})
		rule_ids(asset) == set()
	}
	every fn in ["sign", "verify", "encrypt", "decrypt"] {
		asset := with_properties(component("ML-KEM-768", "", ""), {"primitive": "", "cryptoFunctions": [fn]})
		rule_ids(asset) == set()
	}
}

test_ml_kem_parameter_recommendation if {
	every parameter in ["768", "1024", " ML-KEM-768 ", "ml_kem_1024"] {
		asset := with_properties(component("ML-KEM", "", ""), {"parameterSetIdentifier": parameter})
		rule_ids(asset) == {"ECCG-KEE-002"}
	}
	every parameter in [512, 768, 1024, "512", "ML-KEM-512", "999", "", "malformed", "-768", "7.68", "ML-KEM-7.68", null, {}, [], true, -1, 768.5] {
		asset := with_properties(component("ML-KEM", "", ""), {"parameterSetIdentifier": parameter})
		rule_ids(asset) == {"ECCG-KEE-002", "ECCG-KEE-003"}
	}
}

test_frodokem_parameter_recommendation if {
	every parameter in ["976", "1344", "FrodoKEM-976-AES", "FrodoKEM-1344-SHAKE"] {
		asset := with_properties(component("FrodoKEM", "", ""), {"parameterSetIdentifier": parameter})
		rule_ids(asset) == {"ECCG-KEE-002"}
	}
	every parameter in [640, 976, 1344, "640", "FrodoKEM-640-AES", "ML-KEM-1024", "", "invalid", "-976", "9.76", "FrodoKEM-9.76", null, {}, [], true] {
		asset := with_properties(component("FrodoKEM", "", ""), {"parameterSetIdentifier": parameter})
		rule_ids(asset) == {"ECCG-KEE-002", "ECCG-KEE-004"}
	}
}

test_parameter_oid_overrides_conflicting_fields_and_names if {
	asset := with_properties(component("ML-KEM-1024", "FrodoKEM", " \t2.16.840.1.101.3.4.4.1\n"), {"parameterSetIdentifier": "768"})
	parameter_size(asset) == 512
	rule_ids(asset) == {"ECCG-KEE-002", "ECCG-KEE-003"}
	asset2 := component("FrodoKEM-640", "Kyber", "2.16.840.1.101.3.4.4.3")
	parameter_size(asset2) == 1024
	rule_ids(asset2) == {"ECCG-KEE-002"}
}

test_explicit_invalid_or_lower_parameters_are_not_hidden_by_names if {
	every parameter in ["bad", "FrodoKEM-976", "512"] {
		asset := with_properties(component("ML-KEM-768", "", ""), {"parameterSetIdentifier": parameter})
		rule_ids(asset) == {"ECCG-KEE-002", "ECCG-KEE-003"}
	}
	# The shared getter treats blank and non-string fields as absent.
	every parameter in ["", " \t ", null, {}, [], true, 512] {
		asset := with_properties(component("ML-KEM-768", "", ""), {"parameterSetIdentifier": parameter})
		parameter_size(asset) == 768
		rule_ids(asset) == {"ECCG-KEE-002"}
	}
	asset := with_properties(component("FrodoKEM-1344-AES", "", ""), {"parameterSetIdentifier": "640"})
	parameter_size(asset) == 640
	rule_ids(asset) == {"ECCG-KEE-002", "ECCG-KEE-004"}
	asset2 := component("FrodoKEM-976", "ML-KEM", "")
	parameter_size(asset2) == ""
	rule_ids(asset2) == {"ECCG-KEE-002", "ECCG-KEE-003"}
	asset3 := component("ML-KEM-1024", "ML-KEM-512", "")
	parameter_size(asset3) == 512
	rule_ids(asset3) == {"ECCG-KEE-002", "ECCG-KEE-003"}
}

test_findings_include_correct_notes_and_parameter_metadata if {
	every case in [
		{"asset": component("ML-KEM-512", "", ""), "rule": "ECCG-KEE-003", "note": "64-ML-KEMParameters", "size": 512},
		{"asset": component("FrodoKEM-640-SHAKE", "", ""), "rule": "ECCG-KEE-004", "note": "65-FrodoKEMParameters", "size": 640},
	] {
		result := findings with input as {"components": [case.asset]}
		every finding in result {
			finding.severity == "warning"
			finding.notes.title != "unknown"
			finding.bomRef == "key-establishment-test"
		}
		matching := [finding | some finding in result; finding.ruleId == case.rule]
		count(matching) == 1
		matching[0].notes.title == case.note
		matching[0].parameterSize == case.size
		some authentication in result
		authentication.ruleId == "ECCG-KEE-002"
		authentication.notes.title == "60-KE-Auth"
	}
}

test_aggregate_includes_parameter_and_authentication_findings_once if {
	result := all_findings with input as {"components": [component("ML-KEM-512", "", "")]}
	matching := [finding | some finding in result; startswith(finding.ruleId, "ECCG-KEE-")]
	count(matching) == 2
	{finding.ruleId | some finding in matching} == {"ECCG-KEE-002", "ECCG-KEE-003"}
	every finding in matching {
		finding.section == "Asymmetric Constructions"
		finding.subsection == "Key Establishment and Key Encapsulation Schemes"
	}
}
