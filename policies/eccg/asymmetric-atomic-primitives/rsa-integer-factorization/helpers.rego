package cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.helpers

import data.cbom.eccg.classifying_helpers.is_public_key_eccg_primitive

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one

import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants.MINIMUM_RSA_MODULUS_LENGTH
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants.RSA_PRIMITIVE_FAMILIES
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants.RSA_PRIMITIVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants.RSA_PRIMITIVE_OID_VALUES

rsa_names := {normalize_crypto_identifier(name) |
	some name in RSA_PRIMITIVE_NAMES
}

rsa_families := {normalize_crypto_identifier(family) |
	some family in RSA_PRIMITIVE_FAMILIES
}

rsa_scheme_metadata(component) := {
	"scheme": "RSA",
	"parameterSetIdentifier": get_component_parameter_set_identifier_or_empty(component),
	"modulusBits": get_rsa_modulus_bits_or_empty(component),
	"minimumModulusBits": MINIMUM_RSA_MODULUS_LENGTH,
	"publicExponent": "",
	"exponentCheck": "not_verifiable",
}

# Detect RSA before evaluating its modulus. Other public-key algorithms
# belong to their own atomic-primitive policies.
is_rsa_scheme(component) if {
	is_public_key_eccg_primitive(component)
	oid := get_component_oid_or_empty(component)
	oid in RSA_PRIMITIVE_OID_VALUES
} else if {
	is_public_key_eccg_primitive(component)
	family := get_component_algorithm_family_or_empty(component)
	normalize_crypto_identifier(family) in rsa_families
} else if {
	is_public_key_eccg_primitive(component)
	name := get_component_name_or_empty(component)
	normalized_name := normalize_crypto_identifier(name)
	normalized_name in rsa_names
} else if {
	is_public_key_eccg_primitive(component)
	name := get_component_name_or_empty(component)

	# Registry-style RSA names may append hash, padding, or size parameters.
	regex.match("(^|[-_/ ])(rsa|rsaes|rsassa)([-_/ ]|$)", name)
} else if {
	is_public_key_eccg_primitive(component)
	normalized_name := normalize_crypto_identifier(get_component_name_or_empty(component))
	regex.match("^(rsa[0-9]+|sha[0-9]+withrsa(encryption|andmgf1|pss)?)$", normalized_name)
}

# Use the CBOM's parameterSetIdentifier, not a size embedded in the name.
# Missing, malformed, nonpositive, and fractional lengths are inconclusive.
get_rsa_modulus_bits_or_empty(component) := parameter if {
	parameter := get_component_parameter_set_identifier_to_number_or_negative_one(component)
	is_number(parameter)
	parameter > 0
	floor(parameter) == parameter
} else := ""
