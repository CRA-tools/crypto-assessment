package cbom.eccg.asymmetric_atomic_primitives.ff_dlog

import data.cbom.eccg.general_helpers.build_finding
import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants.MINIMUM_FF_DLOG_GROUP_BITS
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.helpers.AGREED_FF_DLOG_GROUP_FAMILY_LABELS
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.helpers.get_ffdlog_group_bits_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.helpers.get_ffdlog_group_family_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.helpers.get_ffdlog_parameter_set
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.helpers.is_eccg_agreed_ffdlog_group_family
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.helpers.is_ffdlog_primitive

#
# ---------------------------------------------------------
# ECCG-FFDLOG-001
# MODP (RFC3526) and FFDHE (RFC7919) are the only recommended
# finite-field discrete logarithm parameter families.
#
# This rule flags FF-DLOG components that are not identifiable as
# MODP or FFDHE. Generic finite-field DH parameters may be valid in
# other contexts, but they are not among the ECCG recommended
# FF-DLOG parameter families from the table.
# ---------------------------------------------------------
#
findings contains finding if {
	component := input.components[_]

	is_ffdlog_primitive(component)
	not is_eccg_agreed_ffdlog_group_family(component)

	finding := build_finding(
		"ECCG-FFDLOG-001",
		"critical",
		sprintf(
			"FF-DLOG primitive '%s' is not identifiable as an agreed group. Accepted parameter families: %s.",
			[get_component_name_or_empty(component), concat(", ", AGREED_FF_DLOG_GROUP_FAMILY_LABELS)],
		),
		component,
		{
			"scheme": "FF-DLOG",
			"groupFamily": get_ffdlog_group_family_or_empty(component),
			"status": "not_agreed",
			"classification": "non_compliant",
			"allowedFamilies": AGREED_FF_DLOG_GROUP_FAMILY_LABELS,
			"complianceImpact": sprintf("Only the following finite-field discrete logarithm parameter families are ECCG recommended: %s.", [concat(", ", AGREED_FF_DLOG_GROUP_FAMILY_LABELS)]),
		},
	)
}

#
# ---------------------------------------------------------
# ECCG-FFDLOG-002
# MODP (RFC3526) and FFDHE (RFC7919) group size must be >= 3072 bits.
#
# Read the size from parameterSetIdentifier. All groups below the
# minimum are non-compliant regardless of the evaluation date.
# ---------------------------------------------------------
#
findings contains finding if {
	component := input.components[_]

	is_ffdlog_primitive(component)
	is_eccg_agreed_ffdlog_group_family(component)

	p_bits := get_ffdlog_group_bits_or_empty(component)
	p_bits != ""
	p_bits < MINIMUM_FF_DLOG_GROUP_BITS

	finding := build_finding(
		"ECCG-FFDLOG-002",
		"critical",
		sprintf("Group size for %s must be >=%d bits. Detected p=%d bits.", [concat(", ", AGREED_FF_DLOG_GROUP_FAMILY_LABELS), MINIMUM_FF_DLOG_GROUP_BITS, p_bits]),
		component,
		{
			"scheme": "FF-DLOG",
			"groupFamily": get_ffdlog_group_family_or_empty(component),
			"parameterSetIdentifier": get_ffdlog_parameter_set(component),
			"groupBits": p_bits,
			"minimumGroupBits": MINIMUM_FF_DLOG_GROUP_BITS,
			"status": "not_agreed",
			"classification": "non_compliant",
		},
	)
}

#
# ---------------------------------------------------------
# ECCG-FFDLOG-002
# MODP/FFDHE group size could not be determined.
#
# The size requirement cannot be verified without a group-size
# value. This usually means the CBOM should be enriched with a
# numeric parameterSetIdentifier or a standardized parameter set
# identifier such as ffdhe3072 or MODP-3072.
# ---------------------------------------------------------
#
findings contains finding if {
	component := input.components[_]

	is_ffdlog_primitive(component)
	is_eccg_agreed_ffdlog_group_family(component)

	p_bits := get_ffdlog_group_bits_or_empty(component)
	p_bits == ""

	finding := build_finding(
		"ECCG-FFDLOG-002",
		"warning",
		sprintf("Group size for %s must be >=%d bits, but parameterSetIdentifier is missing or does not identify a valid group size.", [concat(", ", AGREED_FF_DLOG_GROUP_FAMILY_LABELS), MINIMUM_FF_DLOG_GROUP_BITS]),
		component,
		{
			"scheme": "FF-DLOG",
			"groupFamily": get_ffdlog_group_family_or_empty(component),
			"parameterSetIdentifier": get_ffdlog_parameter_set(component),
			"groupBits": p_bits,
			"minimumGroupBits": MINIMUM_FF_DLOG_GROUP_BITS,
			"status": "unknown",
			"classification": "inconclusive",
			"complianceImpact": "Unable to verify the ECCG FF-DLOG group-size requirement.",
		},
	)
}
