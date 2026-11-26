package cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization_test

# Focused RSA regressions isolate identifier recognition and the modulus threshold.
# Malformed JSON values are deliberate robustness inputs; full valid CBOMs are covered
# by rsa_cyclonedx_test.rego.

import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.findings
import data.cbom.eccg.compliant as assessment_compliant
import data.cbom.eccg.findings as all_findings
import data.cbom.eccg.test_type_helpers as test_types

# Args:
#   algorithm_name, primitive_type, algorithm_family: string.
#   parameter_set_identifier: any JSON value; normally a modulus-size string,
#       with malformed values supplied to test getter fallbacks.
# Returns: object<string, any> (partial algorithm component), with name,
#   bom-ref, and nested cryptoProperties.algorithmProperties; no type field.
component(algorithm_name, primitive_type, algorithm_family, parameter_set_identifier) := {
	"name": algorithm_name,
	"bom-ref": "rsa-test-component",
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": {
			"primitive": primitive_type,
			"algorithmFamily": algorithm_family,
			"parameterSetIdentifier": parameter_set_identifier,
		},
	},
} if {
	is_string(algorithm_name)
	is_string(primitive_type)
	is_string(algorithm_family)
	test_types.is_json_value(parameter_set_identifier)
}

# Args:
#   test_component: object<string, any> (complete or partial component).
# Returns: object (one RSA finding); undefined unless exactly one exists.
# Locals:
#   actual_findings: set<object> of findings.
#   finding: object (the sole finding).
only_finding_for(test_component) := finding if {
	test_types.is_string_keyed_object(test_component)
	actual_findings := findings with input as {"components": [test_component]}
	is_set(actual_findings)
	test_types.is_findings(actual_findings)
	count(actual_findings) == 1
	some finding in actual_findings
}

# RSA name aliases must activate the same modulus check across encryption, signature,
# and KEM primitives.
test_rsa_encryption_signatures_and_kems_are_detected if {
	every test_case in [
		{"name": "RSA", "primitive": "pke"},
		{"name": "RSA-2048", "primitive": "pke"},
		{"name": "RSA2048", "primitive": "pke"},
		{"name": "RSAES-OAEP", "primitive": "pke"},
		{"name": "RSA-PKCS1-1.5", "primitive": "pke"},
		{"name": "RSASSA-PSS", "primitive": "signature"},
		{"name": "SHA256withRSA", "primitive": "signature"},
		{"name": "SHA1withRSA", "primitive": "signature"},
		{"name": "rsa_pss", "primitive": "signature"},
		{"name": "RSA-PSS-SHA-256-MGF1-SHA-256-32-3072", "primitive": "signature"},
		{"name": "RSA-KEM", "primitive": "kem"},
	] {
		finding := only_finding_for(component(test_case.name, test_case.primitive, "", "2048"))
		finding.ruleId == "ECCG-RSA-001"
		finding.severity == "critical"
		finding.classification == "non_compliant"
		finding.modulusBits == 2048
		finding.exponentCheck == "not_verifiable"
	}
}

# A recognized RSA family must be sufficient when the name is opaque or absent.
test_family_detection_without_recognized_name if {
	every algorithm_family in ["RSA", "RSAES-OAEP", "RSAES-PKCS1", "RSASSA-PSS", "RSASSA-PKCS1", "RSA-X931", "rsassa_pss"] {
		finding := only_finding_for(component("custom name", "signature", algorithm_family, "2048"))
		finding.ruleId == "ECCG-RSA-001"
		finding.classification == "non_compliant"
	}
	test_component := object.remove(component("", "pke", "RSA", "2048"), {"name"})
	finding := only_finding_for(test_component)
	finding.modulusBits == 2048
}

# Registered RSA algorithm OIDs must identify the primitive without a usable name or
# family.
test_oid_detection_without_recognized_name_or_family if {
	every algorithm_oid in ["1.2.840.113549.1.1.1", "1.2.840.113549.1.1.7", "1.2.840.113549.1.1.10", "1.2.840.113549.1.1.11"] {
		test_component := component("custom name", "signature", "", "2048")
		component_with_oid := object.union(test_component, {"cryptoProperties": object.union(test_component.cryptoProperties, {"oid": algorithm_oid})})
		finding := only_finding_for(component_with_oid)
		finding.modulusBits == 2048
		finding.classification == "non_compliant"
	}
}

# A known modulus below 3000 bits produces one critical rejection with the reported size
# and required minimum.
test_undersized_moduli_produce_one_critical_finding if {
	every parameter_set_identifier in ["1", "1024", "2048", "2999"] {
		finding := only_finding_for(component("RSA", "pke", "RSA", parameter_set_identifier))
		finding.severity == "critical"
		finding.classification == "non_compliant"
		finding.modulusBits == to_number(parameter_set_identifier)
		finding.minimumModulusBits == 3000
		finding.parameterSetIdentifier == parameter_set_identifier
	}
}

# Exactly 3000 bits satisfies the current threshold; common larger sizes must also avoid
# a size finding.
test_modulus_minimum_is_inclusive if {
	every parameter_set_identifier in ["3000", "3071", "3072", "4096", "8192"] {
		actual_findings := findings with input as {"components": [component("RSA", "pke", "", parameter_set_identifier)]}
		count(actual_findings) == 0
	}
}

# Pin the current rule’s missing-data behavior: it only rejects a known positive integer
# modulus below the minimum. A large size in the name must not supply missing modulus
# metadata.
test_missing_or_invalid_moduli_produce_no_finding if {
	# The shared CycloneDX getter accepts parameterSetIdentifier strings.
	every parameter_set_identifier in ["", "unknown", "0", "-1", "2999.5", "3000.5", "RSA-3072", 0, 2048, null, true, [], {}] {
		actual_findings := findings with input as {"components": [component("RSA-8192", "pke", "RSA", parameter_set_identifier)]}
		count(actual_findings) == 0
	}
	test_component := {
		"name": "RSA-8192",
		"cryptoProperties": {
			"assetType": "algorithm",
			"algorithmProperties": {"primitive": "pke"},
		},
	}
	actual_findings := findings with input as {"components": [test_component]}
	count(actual_findings) == 0
}

# The declared small modulus must remain visible even when the component name advertises
# a much larger RSA key.
test_parameter_set_takes_precedence_over_name if {
	finding := only_finding_for(component("RSA-8192", "pke", "RSA", "2048"))
	finding.modulusBits == 2048
	finding.severity == "critical"
}

# A public-key primitive alone must not trigger RSA modulus assessment for other
# mathematical constructions.
test_non_rsa_public_key_algorithms_are_excluded if {
	every test_case in [
		{"name": "DH", "primitive": "pke"},
		{"name": "FFDHE", "primitive": "key-agree"},
		{"name": "ECIES", "primitive": "pke"},
		{"name": "DSA", "primitive": "signature"},
		{"name": "ECDSA", "primitive": "signature"},
		{"name": "EdDSA", "primitive": "signature"},
		{"name": "ML-KEM", "primitive": "kem"},
		{"name": "VersaCipher", "primitive": "pke"},
	] {
		actual_findings := findings with input as {"components": [component(test_case.name, test_case.primitive, test_case.name, "2048")]}
		count(actual_findings) == 0
	}
}

# RSA-looking text on a hash, block cipher, or MAC must not enter the public-key modulus
# rule.
test_non_public_key_components_are_excluded if {
	every primitive_type in ["hash", "block-cipher", "mac"] {
		actual_findings := findings with input as {"components": [component("RSA", primitive_type, "RSA", "2048")]}
		count(actual_findings) == 0
	}
}

# The main endpoint must retain exactly one RSA violation, its section metadata, and its
# effect on overall compliance.
test_rsa_findings_reach_top_level_once if {
	test_components := [component("RSA-2048", "pke", "RSA", "2048")]
	aggregate_findings := all_findings with input as {"components": test_components}
	rsa_findings := {finding |
		some finding in aggregate_findings
		startswith(finding.ruleId, "ECCG-RSA-")
	}
	count(rsa_findings) == 1
	some finding in rsa_findings
	finding.section == "Asymmetric Atomic Primitives"
	finding.subsection == "RSA Integer Factorization"
	finding.classification == "non_compliant"
	finding.note.title == "Legacy RSA"
	is_assessment_compliant := assessment_compliant with input as {"components": test_components}
	is_assessment_compliant == false
}

# Missing components are treated as an empty assessment rather than an undefined result.
test_empty_input_has_no_rsa_findings if {
	actual_findings := findings with input as {}
	count(actual_findings) == 0
}
