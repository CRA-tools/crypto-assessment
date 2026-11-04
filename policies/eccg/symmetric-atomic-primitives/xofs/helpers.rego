package cbom.eccg.symmetric_atomic_primitives.xofs.helpers

import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty

import data.cbom.eccg.classifying_helpers.is_xof_primitive

import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.CSHAKE_XOF_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.SHAKE_XOF_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.SHAKE_XOF_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.CSHAKE_XOF_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF

xof_primitive_metadata(component) := {
    "xofBits": get_component_parameter_set_identifier_to_number_or_negative_one(component),
    "minimumRecommendedXofBitsForQuantumSensitiveContext": MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF,
}

xof_scheme_from_identifier(identifier) := normalized if {
    normalized := normalize_crypto_identifier(identifier)
    normalized in {"shake128", "shake256", "cshake128", "cshake256"}
} else := scheme if {
    name_matches := regex.find_all_string_submatch_n(`^(c?shake)[-_ ]?(128|256)([-_/ ][0-9]+)*$`, lower(identifier), 1)
    scheme := concat("", [name_matches[0][1], name_matches[0][2]])
} else := ""

get_xof_scheme_or_empty(component) := normalize_crypto_identifier(scheme) if {
    some scheme, oid in object.union(SHAKE_XOF_ALGORITHM_OIDS, CSHAKE_XOF_ALGORITHM_OIDS)
    oid == get_component_oid_or_empty(component)
} else := scheme if {
    scheme := xof_scheme_from_identifier(get_component_algorithm_family_or_empty(component))
    scheme != ""
} else := xof_scheme_from_identifier(get_component_name_or_empty(component))

is_shake256(component) if {
    is_xof_primitive(component)
    get_xof_scheme_or_empty(component) == "shake256"
}

is_shake128(component) if {
    is_xof_primitive(component)
    get_xof_scheme_or_empty(component) == "shake128"
}

is_cshake256(component) if {
    is_xof_primitive(component)
    get_xof_scheme_or_empty(component) == "cshake256"
}

is_cshake128(component) if {
    is_xof_primitive(component)
    get_xof_scheme_or_empty(component) == "cshake128"
}


is_agreed_xof_component(component) if {
    is_shake256(component)
} else if {
    is_shake128(component)
} else if {
    is_cshake256(component)
} else if {
    is_cshake128(component)
} 

is_xof_output_size_above_quantum_sensitive_threshold(component) if {
    is_xof_primitive(component)
    get_component_parameter_set_identifier_to_number_or_negative_one(component) >= MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF
}

AGREED_XOF_ALGORITHM_NAMES := SHAKE_XOF_ALGORITHM_NAMES | CSHAKE_XOF_ALGORITHM_NAMES
