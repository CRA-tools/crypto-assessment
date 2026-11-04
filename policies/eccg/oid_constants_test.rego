package cbom.eccg.oid_constants_test

# OID placeholder regressions ensure unassigned identifiers cannot grant agreement.
# Synthetic assignments are confined to table overrides inside individual tests.

import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants as finite_field_constants
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.oid_constants.NO_OID
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants as xof_constants
import data.cbom.eccg.symmetric_atomic_primitives.xofs.helpers as xof_helpers
import data.cbom.eccg.test_type_helpers as test_types

# Args:
#   algorithm_name: string.
# Returns: object with name: string and cryptoProperties: object, containing
#   assetType: "algorithm" and algorithmProperties: {primitive: "xof"}.
#   This is a partial component, without type or bom-ref.
xof_component(algorithm_name) := {
	"name": algorithm_name,
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": {"primitive": "xof"},
	},
} if {
	is_string(algorithm_name)
}

# Args:
#   test_component: object<string, any> with a cryptoProperties object.
#   algorithm_oid: any JSON value; malformed values test getter fallbacks.
# Returns: object<string, any> with algorithm_oid in cryptoProperties.oid.
with_oid(test_component, algorithm_oid) := object.union(test_component, {
	"cryptoProperties": object.union(test_component.cryptoProperties, {"oid": algorithm_oid}),
}) if {
	test_types.is_string_keyed_object(test_component)
	test_types.is_string_keyed_object(test_component.cryptoProperties)
	test_types.is_json_value(algorithm_oid)
}

# The NO_OID sentinel must not equal missing, trimmed, or malformed values returned by
# the shared OID getter.
test_placeholder_cannot_match_oid_getter_output if {
	get_component_oid_or_empty({}) != NO_OID
	every algorithm_oid in [NO_OID, trim_space(NO_OID), "", " \t\n", null, 123, true, [], {}, "1.2.3.4"] {
		get_component_oid_or_empty(with_oid(xof_component("unknown"), algorithm_oid)) != NO_OID
	}
}

# Placeholder and unrecognized OID values must not accidentally classify an unknown XOF
# as cSHAKE.
test_unknown_xof_is_not_cshake_without_a_verified_oid if {
	test_component := xof_component("unknown")
	not xof_helpers.is_cshake128(test_component)
	not xof_helpers.is_cshake256(test_component)
	every algorithm_oid in [NO_OID, trim_space(NO_OID), "", " \t\n", null, 123, true, [], {}, "1.2.3.4"] {
		component_with_unrecognized_oid := with_oid(test_component, algorithm_oid)
		not xof_helpers.is_cshake128(component_with_unrecognized_oid)
		not xof_helpers.is_cshake256(component_with_unrecognized_oid)
	}
}

# A missing or unusable OID must still allow a concrete cSHAKE name to identify the
# correct variant.
test_cshake_name_fallback_without_oid if {
	xof_helpers.is_cshake128(xof_component("cSHAKE128"))
	xof_helpers.is_cshake256(xof_component("cSHAKE256"))
	not xof_helpers.is_cshake256(xof_component("cSHAKE128"))
	not xof_helpers.is_cshake128(xof_component("cSHAKE256"))
	every algorithm_oid in [NO_OID, "", null, "1.2.3.4"] {
		xof_helpers.is_cshake128(with_oid(xof_component("cSHAKE128"), algorithm_oid))
		xof_helpers.is_cshake256(with_oid(xof_component("cSHAKE256"), algorithm_oid))
	}
}

# Verified SHAKE OIDs must identify the correct variant when the name supplies no
# evidence.
test_shake_oid_detection_without_name if {
	test_component := xof_component("unknown")
	xof_helpers.is_shake128(with_oid(test_component, "2.16.840.1.101.3.4.2.11"))
	xof_helpers.is_shake256(with_oid(test_component, "2.16.840.1.101.3.4.2.12"))
}

# Synthetic OIDs verify that both existing detection branches remain usable
# when verified OIDs replace the placeholders in the table.
# Table overrides exercise both cSHAKE OID branches while keeping the synthetic values
# confined to the test.
test_cshake_oid_detection_is_preserved if {
	synthetic_cshake_oids := {"CSHAKE128": "1.2.3.128", "CSHAKE256": "1.2.3.256"}
	cshake128_component := with_oid(xof_component("unknown"), synthetic_cshake_oids.CSHAKE128)
	cshake256_component := with_oid(xof_component("unknown"), synthetic_cshake_oids.CSHAKE256)
	xof_helpers.is_cshake128(cshake128_component) with xof_constants.CSHAKE_XOF_ALGORITHM_OIDS as synthetic_cshake_oids
	xof_helpers.is_cshake256(cshake256_component) with xof_constants.CSHAKE_XOF_ALGORITHM_OIDS as synthetic_cshake_oids
	not xof_helpers.is_cshake128(cshake256_component) with xof_constants.CSHAKE_XOF_ALGORITHM_OIDS as synthetic_cshake_oids
	not xof_helpers.is_cshake256(cshake128_component) with xof_constants.CSHAKE_XOF_ALGORITHM_OIDS as synthetic_cshake_oids
}

# Until verified MODP/FFDHE OIDs are present, their matching sets must exclude
# placeholders and remain empty.
test_unassigned_finite_field_oids_remain_excluded if {
	finite_field_constants.MODP_FF_DLOG_SCHEME_OID_VALUES == set()
	finite_field_constants.FFDHE_FF_DLOG_SCHEME_OID_VALUES == set()
}
