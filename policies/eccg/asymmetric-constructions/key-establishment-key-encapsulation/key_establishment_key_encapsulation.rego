package cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation

import data.cbom.eccg.general_helpers.build_finding
import data.cbom.eccg.getter_helpers.get_note

import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.constants.RECOMMENDED_FRODOKEM_PARAMETER_SIZES
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.constants.RECOMMENDED_ML_KEM_PARAMETER_SIZES
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.AGREED_KEY_ESTABLISHMENT_SCHEMES
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.get_kem_parameter_size_or_empty
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.get_key_establishment_scheme_or_empty
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.is_agreed_key_establishment_scheme
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.is_key_establishment_component
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.kem_parameter_description
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.kem_parameter_metadata
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.key_establishment_metadata

default compliant := false

compliant if count(findings) == 0

SECTION := "Asymmetric-Constructions"
SUBSECTION := "Key-Establishment-and-Key-Encapsulation-Schemes"

# ECCG-KEE-001: Both A and R entries in the supplied table are agreed.
findings contains finding if {
	some component in input.components
	is_key_establishment_component(component)
	not is_agreed_key_establishment_scheme(component)
	metadata := key_establishment_metadata(component)

	finding := build_finding(
		"ECCG-KEE-001",
		"critical",
		sprintf("Key establishment or key encapsulation scheme '%s' is not in the ECCG agreed scheme list. The agreed schemes are: %s.", [metadata.schemeIdentifier, concat(", ", sort(AGREED_KEY_ESTABLISHMENT_SCHEMES))]),
		component,
		metadata,
	)
}

# ECCG-KEE-002 / 60-KE-Auth: A CBOM does not prove party authentication.
findings contains finding if {
	some component in input.components
	is_agreed_key_establishment_scheme(component)
	metadata := key_establishment_metadata(component)

	finding := build_finding(
		"ECCG-KEE-002",
		"warning",
		sprintf("%s detected. Participating parties and exchanged key-establishment data must be authenticated. Verify authentication of public values, keys/ciphertexts, and identities.", [metadata.schemeIdentifier]),
		component,
		object.union(metadata, {"notes": get_note(SECTION, SUBSECTION, "60-KE-Auth")}),
	)
}

# ECCG-KEE-003 / 64-ML-KEMParameters: A recommendation, not a scheme rejection.
findings contains finding if {
	some component in input.components
	is_agreed_key_establishment_scheme(component)
	get_key_establishment_scheme_or_empty(component) == "ML-KEM"
	not get_kem_parameter_size_or_empty(component) in RECOMMENDED_ML_KEM_PARAMETER_SIZES

	finding := build_finding(
		"ECCG-KEE-003",
		"warning",
		sprintf("ML-KEM uses %s. Use the highest possible standardized parameter size; the recommended parameter sizes are %v.", [kem_parameter_description(component), sort(RECOMMENDED_ML_KEM_PARAMETER_SIZES)]),
		component,
		object.union(kem_parameter_metadata(component), {"notes": get_note(SECTION, SUBSECTION, "64-ML-KEMParameters")}),
	)
}

# ECCG-KEE-004 / 65-FrodoKEMParameters: Warn for lower or undetermined sizes.
findings contains finding if {
	some component in input.components
	is_agreed_key_establishment_scheme(component)
	get_key_establishment_scheme_or_empty(component) == "FrodoKEM"
	not get_kem_parameter_size_or_empty(component) in RECOMMENDED_FRODOKEM_PARAMETER_SIZES

	finding := build_finding(
		"ECCG-KEE-004",
		"warning",
		sprintf("FrodoKEM uses %s. Use the highest possible standardized parameter size; the recommended parameter sizes are %v.", [kem_parameter_description(component), sort(RECOMMENDED_FRODOKEM_PARAMETER_SIZES)]),
		component,
		object.union(kem_parameter_metadata(component), {"notes": get_note(SECTION, SUBSECTION, "65-FrodoKEMParameters")}),
	)
}
