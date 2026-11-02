package cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes_test

# Focused asymmetric-encryption regressions cover identifier precedence, inference when
# the primitive is absent, and note selection. Partial and malformed records here
# complement the complete CycloneDX section fixtures.

import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.findings
import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.constants.ASYMMETRIC_ENCRYPTION_OIDS
import data.cbom.eccg.findings as all_findings
import data.cbom.eccg.test_type_helpers as test_types

# Args:
#   algorithm_name, algorithm_family: string.
#   algorithm_oid: any JSON value; malformed values test getter fallbacks.
# Returns: object<string, any> (partial algorithm component), with name,
#   bom-ref, and nested cryptoProperties; defaults to primitive "pke" and
#   parameterSetIdentifier "3072", and has no type field.
component(algorithm_name, algorithm_family, algorithm_oid) := {
	"name": algorithm_name,
	"bom-ref": "encryption-test",
	"cryptoProperties": {
		"assetType": "algorithm",
		"oid": algorithm_oid,
		"algorithmProperties": {
			"primitive": "pke",
			"algorithmFamily": algorithm_family,
			"parameterSetIdentifier": "3072",
		},
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
#   test_component: object with cryptoProperties.algorithmProperties: object.
#   primitive_type: string; an empty string tests missing-primitive inference.
# Returns: object<string, any> (component with the supplied primitive).
with_primitive(test_component, primitive_type) := with_properties(test_component, {"primitive": primitive_type}) if {
	test_types.is_string_keyed_object(test_component)
	is_string(primitive_type)
}

# Violations and advisories are independent findings. Require exactly
# one finding for the requested rule, without suppressing the other rules.
# Args:
#   test_component: object<string, any> (complete or partial component).
#   rule_id: string (ECCG rule identifier).
# Returns: object (one finding); undefined unless exactly one matches rule_id.
# Locals:
#   actual_findings: set<object> of findings.
#   matching_findings: array<object> of findings for rule_id.
#   finding: object (one finding).
rule_finding(test_component, rule_id) := matching_findings[0] if {
	test_types.is_string_keyed_object(test_component)
	is_string(rule_id)
	actual_findings := findings with input as {"components": [test_component]}
	is_set(actual_findings)
	test_types.is_findings(actual_findings)
	matching_findings := [finding | some finding in actual_findings; finding.ruleId == rule_id]
	count(matching_findings) == 1
}

# Args:
#   test_component: object<string, any> (complete or partial component).
# Returns: object (one ECCG-AS-ENC-001 finding); undefined unless exactly one exists.
only_finding(test_component) := rule_finding(test_component, "ECCG-AS-ENC-001") if {
	test_types.is_string_keyed_object(test_component)
}

# Verify OAEP recognition independently through its OID, family, and name, including
# expected advisories.
test_oaep_by_oid_family_and_name if {
	every test_component in [
		component("", "", "1.2.840.113549.1.1.7"),
		component("custom", "RSAES-OAEP", ""),
		component("RSA-OAEP", "RSA", ""),
		component(" rsaes_oaep ", "", ""),
		component("OAEP", "", ""),
		component("RSA-OAEP-SHA-256-MGF1-3072", "", ""),
		component("RSA/ECB/OAEPPadding", "", ""),
		component("RSA/None/OAEPWithSHA-256AndMGF1Padding", "", ""),
	] {
		actual_findings := findings with input as {"components": [test_component]}
		{finding.ruleId | some finding in actual_findings} == {"ECCG-AS-ENC-002", "ECCG-AS-ENC-004", "ECCG-AS-ENC-005"}
		count(actual_findings) == 3
		every finding in actual_findings {
			finding.severity == "warning"
			finding.schemeIdentifier == "RSAES-OAEP"
			finding.bomRef == "encryption-test"
		}
	}
}

# Verify PKCS#1 v1.5 recognition through each identifier and preserve its padding-oracle
# review requirement.
test_pkcs1_v1_5_by_oid_family_and_name if {
	every test_component in [
		component("", "", "1.2.840.113549.1.1.1"),
		component("custom", "RSAES-PKCS1", ""),
		component("custom", "RSAES-PKCS1-v1_5", ""),
		component("custom", "rsaes_pkcs1_v1_5", ""),
		component("RSAES-PKCS1-v1_5", "", ""),
		component("RSA-PKCS1-1.5-3072", "RSA", ""),
		component("PKCS1v15", "", ""),
		component("RSA/ECB/PKCS1Padding", "", ""),
	] {
		actual_findings := findings with input as {"components": [test_component]}
		{finding.ruleId | some finding in actual_findings} == {"ECCG-AS-ENC-002", "ECCG-AS-ENC-003", "ECCG-AS-ENC-005"}
		count(actual_findings) == 3
		every finding in actual_findings {
			finding.severity == "warning"
			finding.schemeIdentifier == "RSAES-PKCS1-v1_5"
		}
	}
}

# Getter normalization must retain the priority of a registered OID when surrounding
# labels use whitespace or mixed case.
test_padded_identifiers_and_mixed_case_enums_preserve_oid_precedence if {
	test_component := with_primitive(component(" ElGamal ", " ECIES ", " \t1.2.840.113549.1.1.7\n"), " PKE ")
	component_with_padded_asset_type := object.union(test_component, {"cryptoProperties": object.union(test_component.cryptoProperties, {"assetType": " Algorithm "})})
	finding := rule_finding(component_with_padded_asset_type, "ECCG-AS-ENC-004")
	finding.schemeIdentifier == "RSAES-OAEP"
	finding.oid == "1.2.840.113549.1.1.7"
	finding.component == "elgamal"
}

# Unusable OID data must not prevent a recognized encryption family from supplying the
# scheme.
test_unknown_or_malformed_oids_allow_family_fallback if {
	every algorithm_oid in ["", "1.2.3.4.5", "not-an-oid", null, 7, [], {}] {
		finding := rule_finding(component("unrecognized", "RSAES-OAEP", algorithm_oid), "ECCG-AS-ENC-004")
		finding.schemeIdentifier == "RSAES-OAEP"
	}
}

# Contradictory labels must resolve deterministically so an attractive name cannot
# override stronger identifier evidence.
test_oid_and_family_take_priority_over_names if {
	every test_case in [
		{"oid": "1.2.840.113549.1.1.7", "family": "RSAES-PKCS1", "name": "ElGamal", "scheme": "RSAES-OAEP"},
		{"oid": "1.2.840.113549.1.1.1", "family": "RSAES-OAEP", "name": "RSA-OAEP", "scheme": "RSAES-PKCS1-v1_5"},
		{"oid": "", "family": "RSAES-OAEP", "name": "RSA-PKCS1-1.5", "scheme": "RSAES-OAEP"},
		{"oid": "", "family": "RSAES-PKCS1", "name": "RSA-OAEP", "scheme": "RSAES-PKCS1-v1_5"},
	] {
		finding := rule_finding(component(test_case.name, test_case.family, test_case.oid), "ECCG-AS-ENC-002")
		finding.schemeIdentifier == test_case.scheme
	}
}

# Detect encryption usage first, then reject schemes outside the two agreed RSA padding
# constructions.
test_other_encryption_schemes_are_rejected if {
	every algorithm_name in ["ECIES", "ElGamal", "RSA/ECB/NoPadding", "RSA-NoPadding", "CustomPKE", "not-RSA-OAEP", "OAEP-wrapper", "RSA-OAEPwrapper", "RSA-PKCS1-1.50"] {
		finding := only_finding(component(algorithm_name, "", ""))
		finding.severity == "critical"
		contains(finding.message, lower(algorithm_name))
		contains(finding.message, "RSAES-OAEP")
		contains(finding.message, "RSAES-PKCS1-v1_5")
	}
}

# A generic RSA family must not turn explicitly unpadded encryption into an agreed
# padded scheme.
test_generic_rsa_family_does_not_hide_unpadded_encryption if {
	finding := only_finding(component("RSA/ECB/NoPadding", "RSA", ""))
	finding.severity == "critical"
}

# Declared encryption usage with missing or unknown scheme identifiers must remain a
# critical finding.
test_unidentified_encryption_schemes_are_not_in_the_agreed_list if {
	every test_component in [
		component("", "", ""),
		component("RSA", "", ""),
		component("RSA-3072", "RSA", ""),
		component("RSA3072", "", ""),
		component("custom", "RSA", ""),
		component("", "RSA", ""),
	] {
		finding := only_finding(test_component)
		finding.severity == "critical"
	}
}

# An encryption-looking label must not override an explicitly different primitive
# category.
test_non_encryption_primitives_are_excluded if {
	every primitive_type in ["signature", "kem", "key-agree", "hash", "block-cipher"] {
		test_component := with_primitive(component("RSA-OAEP", "RSAES-OAEP", "1.2.840.113549.1.1.7"), primitive_type)
		actual_findings := findings with input as {"components": [test_component]}
		count(actual_findings) == 0
	}
}

# A key asset is not an encryption operation; it must not receive scheme-agreement
# findings from this section.
test_key_material_is_excluded if {
	test_component := component("RSA-OAEP", "RSAES-OAEP", "1.2.840.113549.1.1.7")
	key_material_component := object.union(test_component, {"cryptoProperties": object.union(test_component.cryptoProperties, {"assetType": "related-crypto-material"})})
	actual_findings := findings with input as {"components": [key_material_component]}
	count(actual_findings) == 0
}

# Agreed schemes retain distinct advisories for random padding, scheme-specific
# decoding/oracle handling, and quantum resistance.
test_padding_and_quantum_notes_are_separate_rules if {
	every test_case in [
		{"asset": component("RSA-OAEP", "", ""), "scheme": "RSAES-OAEP", "notes": {
			"ECCG-AS-ENC-002": "43-RandomPadding",
			"ECCG-AS-ENC-004": "45-OAEP-PaddingAttack",
			"ECCG-AS-ENC-005": "46-QuantumThreat",
		}},
		{"asset": component("RSA-PKCS1-1.5", "", ""), "scheme": "RSAES-PKCS1-v1_5", "notes": {
			"ECCG-AS-ENC-002": "43-RandomPadding",
			"ECCG-AS-ENC-003": "44-PaddingAttack",
			"ECCG-AS-ENC-005": "46-QuantumThreat",
		}},
	] {
		actual_findings := findings with input as {"components": [test_case.asset]}
		count(actual_findings) == 3
		every rule_id, expected_note_title in test_case.notes {
			advisory_finding := rule_finding(test_case.asset, rule_id)
			advisory_finding.severity == "warning"
			advisory_finding.notes.title == expected_note_title
			advisory_finding.notes.text != ""
			advisory_finding.schemeIdentifier == test_case.scheme
			advisory_finding.bomRef == "encryption-test"
		}
	}
}

# Both critical rejections and operational warnings must be visible through the main
# assessment endpoint.
test_violation_and_advisory_findings_reach_top_level if {
	test_components := [component("RSA-OAEP", "", ""), component("RSA-PKCS1-1.5", "", ""), component("ElGamal", "", "")]
	aggregate_findings := all_findings with input as {"components": test_components}
	encryption_findings := [finding | some finding in aggregate_findings; startswith(finding.ruleId, "ECCG-AS-ENC-")]
	count(encryption_findings) == 7
	count([finding | some finding in encryption_findings; finding.ruleId == "ECCG-AS-ENC-001"]) == 1
	every finding in encryption_findings {
		finding.section == "Asymmetric Constructions"
		finding.subsection == "Asymmetric Encryption Schemes"
		finding.bomRef == "encryption-test"
	}
}

# Missing or empty component collections must yield no section findings.
test_empty_input_produces_no_findings if {
	every input_document in [{}, {"components": []}, {"components": [{}]}] {
		actual_findings := findings with input as input_document
		count(actual_findings) == 0
	}
}

# Findings expose the resolved scheme and raw identifier metadata using the section’s
# current result contract.
test_metadata_contains_scheme_details_without_classification if {
	every test_component in [
		component("", "", "1.2.840.113549.1.1.7"),
		component("custom", "rsaes_oaep", ""),
		component("RSA-OAEP", "unknown-family", ""),
		component("ElGamal", "", ""),
		component("", "", ""),
	] {
		actual_findings := findings with input as {"components": [test_component]}
		count(actual_findings) > 0
		every finding in actual_findings {
			is_string(finding.schemeIdentifier)
			is_string(finding.oid)
			is_string(finding.algorithmFamily)
			not finding.classification
			not finding.status
			not finding.classificationMethod
			not finding.matchedIdentifier
		}
	}
}

# When primitive metadata is absent, an explicit encryption scheme or permitted
# encrypt/decrypt evidence can establish context.
test_missing_primitive_can_use_explicit_encryption_evidence if {
	every test_component in [
		component("", "", "1.2.840.113549.1.1.7"),
		component("custom", "RSAES-OAEP", ""),
		component("RSA-OAEP", "", ""),
	] {
		component_without_primitive := with_primitive(test_component, "")
		finding := rule_finding(component_without_primitive, "ECCG-AS-ENC-004")
		finding.schemeIdentifier == "RSAES-OAEP"
		actual_findings := findings with input as {"components": [component_without_primitive]}
		count(actual_findings) == 3
	}
	finding := only_finding(with_properties(component("RSA", "RSA", ""), {"primitive": "", "cryptoFunctions": ["decrypt"]}))
	finding.severity == "critical"
}

# Signing evidence and bare RSA key identifiers must not be misinterpreted as an
# encryption operation.
test_signature_functions_and_generic_keys_do_not_imply_encryption if {
	every test_component in [
		with_properties(component("RSA-OAEP", "RSAES-OAEP", ""), {"primitive": "", "cryptoFunctions": ["sign"]}),
		with_properties(component("RSA-OAEP", "RSAES-OAEP", ""), {"primitive": "", "cryptoFunctions": ["verify"]}),
		with_primitive(component("RSA", "RSA", "1.2.840.113549.1.1.1"), ""),
		with_properties(component("AES", "AES", ""), {"primitive": "", "cryptoFunctions": ["encrypt"]}),
	] {
		actual_findings := findings with input as {"components": [test_component]}
		count(actual_findings) == 0
	}
}

# Mixed-case and padded crypto-function entries must behave consistently with the shared
# getter.
test_crypto_function_checks_use_the_shared_normalization if {
	every crypto_functions in [[" EnCrYpT ", null], [" DeCrYpT "], " DeCrYpT "] {
		test_component := with_properties(component("RSA", "RSA", ""), {"primitive": "", "cryptoFunctions": crypto_functions})
		finding := only_finding(test_component)
		finding.severity == "critical"
	}
	every crypto_functions in [[" SIGN "], [" VeRiFy "], [" ENCRYPT ", " SIGN "], " VeRiFy "] {
		test_component := with_properties(component("RSA-OAEP", "RSAES-OAEP", ""), {"primitive": "", "cryptoFunctions": crypto_functions})
		findings == set() with input as {"components": [test_component]}
	}
}

# Encryption evidence and scheme detection must use the same OID table. A synthetic entry
# exercises that relationship without relying on the registered OAEP OID.
# Changing the imported identifier table in a test must change recognition, guarding
# against duplicated OID literals in helper logic.
test_encryption_evidence_uses_the_oid_constants if {
	synthetic_encryption_oids := {"1.2.3.7": "RSAES-OAEP"}
	test_component := with_primitive(component("", "", "1.2.3.7"), "")
	actual_findings := findings with input as {"components": [test_component]} with ASYMMETRIC_ENCRYPTION_OIDS as synthetic_encryption_oids
	count(actual_findings) == 3
	every finding in actual_findings {
		finding.severity == "warning"
		finding.schemeIdentifier == "RSAES-OAEP"
		finding.oid == "1.2.3.7"
	}
	component_with_unregistered_oid := with_primitive(component("", "", "1.2.840.113549.1.1.7"), "")
	findings == set() with input as {"components": [component_with_unregistered_oid]} with ASYMMETRIC_ENCRYPTION_OIDS as synthetic_encryption_oids
}

# When primitive metadata is absent, a signature or KEM family must block contradictory
# name-based encryption inference.
test_signature_and_kem_families_disambiguate_names_without_a_primitive if {
	every test_component in [
		component("RSA-PKCS1-1.5", "RSASSA-PKCS1", ""),
		component("RSA-OAEP", "RSASSA-PSS", ""),
		component("RSA-PKCS1-1.5", "RSA-X931", ""),
		component("ECIES", "ECIES-KEM", ""),
		component("RSA-OAEP", "RSA-KEM", ""),
		component("ECIES-KEM", "", ""),
	] {
		actual_findings := findings with input as {"components": [with_primitive(test_component, "")]}
		count(actual_findings) == 0
	}
}

# Advisories follow the resolved scheme, even when the name contradicts it.
# This prevents an OAEP name from adding an OAEP decoding warning to a
# component detected as PKCS#1 v1.5 through its higher-priority OID.
# Operational notes must be selected from the resolved scheme rather than a
# contradictory component name.
test_advisories_follow_the_resolved_scheme if {
	every test_case in [
		{"asset": component("RSA-OAEP", "RSAES-OAEP", "1.2.840.113549.1.1.1"), "rules": {"ECCG-AS-ENC-002", "ECCG-AS-ENC-003", "ECCG-AS-ENC-005"}},
		{"asset": component("RSA-PKCS1-1.5", "RSAES-PKCS1", "1.2.840.113549.1.1.7"), "rules": {"ECCG-AS-ENC-002", "ECCG-AS-ENC-004", "ECCG-AS-ENC-005"}},
		{"asset": component("RSA-OAEP", "RSAES-PKCS1", ""), "rules": {"ECCG-AS-ENC-002", "ECCG-AS-ENC-003", "ECCG-AS-ENC-005"}},
		{"asset": component("RSA-OAEP", "ElGamal", ""), "rules": {"ECCG-AS-ENC-001"}},
	] {
		actual_findings := findings with input as {"components": [test_case.asset]}
		{finding.ruleId | some finding in actual_findings} == test_case.rules
		count(actual_findings) == count(test_case.rules)
	}
}

# Rejected schemes receive one rejection and no operational notes belonging to the
# agreed RSA encryption schemes.
test_non_agreed_schemes_have_one_critical_finding_and_no_scheme_notes if {
	every test_component in [
		component("", "", ""),
		component("custom", "RSA", ""),
		component("RSA-3072", "", ""),
		component("ElGamal", "", ""),
		component("ECIES", "", ""),
		component("RSA/ECB/NoPadding", "RSA", ""),
	] {
		actual_findings := findings with input as {"components": [test_component]}
		count(actual_findings) == 1
		some finding in actual_findings
		finding.ruleId == "ECCG-AS-ENC-001"
		finding.severity == "critical"
		not finding.notes
	}
}
