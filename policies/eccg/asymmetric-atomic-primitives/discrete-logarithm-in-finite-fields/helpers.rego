package cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.helpers

import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.AGREED_FF_DLOG_GROUP_FAMILIES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.FFDHE_FF_DLOG_SCHEME_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.FFDHE_FF_DLOG_SCHEME_OID_VALUES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.FF_DLOG_CANDIDATE_FAMILIES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.FF_DLOG_CANDIDATE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.FF_DLOG_DOMAIN_DEPENDENT_KEY_AGREEMENT_FAMILIES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.FF_DLOG_DOMAIN_DEPENDENT_KEY_AGREEMENT_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.MODP_FF_DLOG_IKE_GROUP_IDS
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.MODP_FF_DLOG_SCHEME_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.MODP_FF_DLOG_SCHEME_OID_VALUES

import data.cbom.eccg.general_helpers.normalize_crypto_identifier
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty

AGREED_FF_DLOG_GROUP_FAMILY_LABELS := sort([sprintf("%s (%s)", [family, reference]) |
	some family, reference in AGREED_FF_DLOG_GROUP_FAMILIES
])

ffdlog_names := {normalize_crypto_identifier(name) |
	some name in FF_DLOG_CANDIDATE_NAMES
}

# MQV and PAKE family names alone do not establish a finite-field domain.
# Their explicit finite-field variants are covered by FF_DLOG_CANDIDATE_NAMES.
ffdlog_families := {normalize_crypto_identifier(family) |
	some family in (FF_DLOG_CANDIDATE_FAMILIES - FF_DLOG_DOMAIN_DEPENDENT_KEY_AGREEMENT_FAMILIES)
}

modp_names := {normalize_crypto_identifier(name) |
	some name in MODP_FF_DLOG_SCHEME_NAMES
}

ffdhe_names := {normalize_crypto_identifier(name) |
	some name in FFDHE_FF_DLOG_SCHEME_NAMES
}

finite_field_variant_names := {normalize_crypto_identifier(name) |
	some name in FF_DLOG_DOMAIN_DEPENDENT_KEY_AGREEMENT_NAMES
}

is_ffdlog_primitive(component) if {
	normalize_crypto_identifier(get_component_name_or_empty(component)) in (ffdlog_names | ffdlog_families)
} else if {
	normalize_crypto_identifier(get_component_algorithm_family_or_empty(component)) in ffdlog_families
} else if {
	get_ffdlog_group_family_or_empty(component) != ""
} else if {
	normalize_crypto_identifier(get_component_primitive_or_empty(component)) == "ffdlog"
} else if {
	name := normalize_crypto_identifier(get_component_name_or_empty(component))
	regex.match("^(dh|dhe|ffdh|ffdhe|modp|ffdlog)[0-9]+$", name)
} else if {
	name := normalize_crypto_identifier(get_component_name_or_empty(component))
	regex.match("^(dsa[0-9]+|sha[0-9]+withdsa|dsa(with)?sha[0-9]+)$", name)
}

# Both scheme-family constants contain FFDH, which cannot distinguish
# approved MODP/FFDHE parameters from arbitrary finite-field DH parameters.
group_family_for_identifier(identifier) := "MODP" if {
	normalize_crypto_identifier(identifier) in (modp_names | {"modp"})
} else := "FFDHE" if {
	normalize_crypto_identifier(identifier) in (ffdhe_names | {"ffdhe"})
} else := "MODP" if {
	normalized := normalize_crypto_identifier(identifier)
	normalized in finite_field_variant_names
	endswith(normalized, "modp")
} else := "FFDHE" if {
	normalized := normalize_crypto_identifier(identifier)
	normalized in finite_field_variant_names
	endswith(normalized, "ffdhe")
} else := ""

# Reuse the shared getters, retaining support for CBOMs with numeric values.
# The shared parameter-set getter accepts only strings.
get_ffdlog_parameter_set(component) := parameter if {
	parameter := get_component_parameter_set_identifier_or_empty(component)
	parameter != ""
} else := ""

get_ffdlog_parameter_set_number(component) := bits if {
	bits := get_component_parameter_set_identifier_to_number_or_negative_one(component)
	bits != -1
} else := bits if {
	bits := get_ffdlog_parameter_set(component)
	is_number(bits)
} else := -1

# An explicit parameter group takes precedence over an OID or scheme name/family.
# OID value sets exclude NO_OID placeholders until verified OIDs are supplied.
# FFDH alone identifies a construction, not an approved parameter family.
get_ffdlog_group_family_or_empty(component) := family if {
	parameter := get_ffdlog_parameter_set(component)
	is_string(parameter)
	parameter != ""
	family := group_family_for_identifier(parameter)
	family != ""
} else := "MODP" if {
	oid := get_component_oid_or_empty(component)
	oid != ""
	oid in MODP_FF_DLOG_SCHEME_OID_VALUES
} else := "FFDHE" if {
	oid := get_component_oid_or_empty(component)
	oid != ""
	oid in FFDHE_FF_DLOG_SCHEME_OID_VALUES
} else := family if {
	family := group_family_for_identifier(get_component_name_or_empty(component))
	family != ""
} else := family if {
	family := group_family_for_identifier(get_component_algorithm_family_or_empty(component))
	family != ""
} else := ""

is_eccg_agreed_ffdlog_group_family(component) if {
	get_ffdlog_group_family_or_empty(component) in object.keys(AGREED_FF_DLOG_GROUP_FAMILIES)
}

# Read the size only from parameterSetIdentifier. A size embedded in the
# component name must not hide a missing, invalid, or smaller parameter set.
get_ffdlog_group_bits_or_empty(component) := bits if {
	bits := get_ffdlog_parameter_set_number(component)
	is_number(bits)
	bits > 0
	floor(bits) == bits
} else := bits if {
	parameter := get_ffdlog_parameter_set(component)
	is_string(parameter)
	normalized := normalize_crypto_identifier(parameter)
	normalized in (modp_names | ffdhe_names)
	not startswith(normalized, "modpgroup")
	numbers := regex.find_n("[0-9]+", normalized, 1)
	bits := to_number(numbers[0])
} else := bits if {
	parameter := get_ffdlog_parameter_set(component)
	is_string(parameter)
	normalized := normalize_crypto_identifier(parameter)
	some group, id in MODP_FF_DLOG_IKE_GROUP_IDS
	normalized == sprintf("modpgroup%d", [id])
	bits := to_number(trim_prefix(group, "MODP-"))
} else := ""
