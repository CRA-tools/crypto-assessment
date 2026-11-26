package cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_note

import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.helpers.get_rsa_modulus_bits_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.helpers.is_rsa_scheme
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.helpers.rsa_scheme_metadata

import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants.MINIMUM_RSA_MODULUS_LENGTH

RSA_SECTION := "Asymmetric-Atomic-Primitives"
RSA_SUBSECTION := "RSA-Integer-Factorization"

#
# ---------------------------------------------------------
# ECCG-RSA-001
# Detect RSA first, then enforce the minimum modulus size from constants.
# An undersized RSA modulus is critical and non-compliant.
#
# Limitation:
# - CycloneDX data does not reliably expose RSA public exponent e.
# - Therefore log2(e) > 16 cannot be verified from the CBOM.
# - This rule checks only the available modulus size n.
# ---------------------------------------------------------
#
findings contains finding if {
	some component in input.components
	is_rsa_scheme(component)

	modulus_bits := get_rsa_modulus_bits_or_empty(component)
	modulus_bits != ""
	modulus_bits < MINIMUM_RSA_MODULUS_LENGTH

	note := get_note(RSA_SECTION, RSA_SUBSECTION, "30-LegacyRSA")

	finding := build_finding(
		"ECCG-RSA-001",
		"critical",
		sprintf("RSA primitive '%s' uses a %d-bit modulus. The modulus size must be >=%d bits.", [get_component_name_or_empty(component), modulus_bits, MINIMUM_RSA_MODULUS_LENGTH]),
		component,
		object.union(
			rsa_scheme_metadata(component),
			{
				"status": "not_agreed",
				"classification": "non_compliant",
				"note": note,
			},
		),
	)
}

