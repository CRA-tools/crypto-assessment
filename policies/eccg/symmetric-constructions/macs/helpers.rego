package cbom.eccg.symmetric_constructions.macs.helpers

import data.cbom.eccg.general_helpers.normalize_crypto_identifier
import data.cbom.eccg.general_helpers.is_legacy_marker_active

import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty

import data.cbom.eccg.classifying_helpers.is_mac_primitive
import data.cbom.eccg.classifying_helpers.is_symmetric_encryption_scheme

import data.cbom.eccg.relationship_helpers.components_share_evidence_window


import data.cbom.eccg.symmetric_constructions.macs.constants.HMAC_MAC_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.macs.constants.CMAC_MAC_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.macs.constants.GMAC_MAC_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.macs.constants.CBC_MAC_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.macs.constants.KMAC_MAC_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.macs.constants.HMAC_MAC_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.macs.constants.HMAC_MAC_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_constructions.macs.constants.HMAC_SHA1_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.macs.constants.HMAC_SHA1_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.macs.constants.HMAC_SHA1_LEGACY_MARKER
import data.cbom.eccg.symmetric_constructions.macs.constants.KMAC_MAC_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.macs.constants.KMAC_MAC_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_constructions.macs.constants.GMAC_MAC_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.macs.constants.CMAC_MAC_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.macs.constants.CMAC_MAC_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_constructions.macs.constants.CBC_MAC_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.macs.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_MACS
import data.cbom.eccg.symmetric_constructions.macs.constants.MINIMUM_MAC_BITS_TRUNCATED_OUTPUT

mac_scheme_metadata(component) := {
    "primitive": get_component_primitive_or_empty(component),
    # this is the max security of the algorithm not the actual key bits
    "keyBits": get_component_parameter_set_identifier_to_number_or_negative_one(component),
    "minimumMacBits": MINIMUM_MAC_BITS_TRUNCATED_OUTPUT,
    "minimumRecommendedBitsForQuantumSensitiveContext": MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_MACS,
}

is_hmac_scheme(component) if {
    is_mac_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in HMAC_MAC_ALGORITHM_OID_VALUES
} else if {
    is_mac_primitive(component)
    algorithm_family := get_component_algorithm_family_or_empty(component)
    some known_family in HMAC_MAC_ALGORITHM_FAMILIES
    algorithm_family == lower(known_family)
} else if {
    is_mac_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "hmac")
} 

is_hmac_sha1_scheme(component) if {
    is_mac_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in HMAC_SHA1_ALGORITHM_OID_VALUES
} else if {
    is_mac_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "hmacsha1")
}

is_kmac_scheme(component) if {
    is_mac_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in KMAC_MAC_ALGORITHM_OID_VALUES
} else if {
    is_mac_primitive(component)
    algorithm_family := get_component_algorithm_family_or_empty(component)
    some known_family in KMAC_MAC_ALGORITHM_FAMILIES
    algorithm_family == lower(known_family)
} else if {
    is_mac_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "kmac")
}

is_gmac_scheme(component) if {
    is_mac_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in GMAC_MAC_ALGORITHM_OID_VALUES
} else if {
    is_mac_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "gmac")
}

is_cmac_scheme(component) if {
    is_mac_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in CMAC_MAC_ALGORITHM_OID_VALUES
} else if {
    is_mac_primitive(component)
    algorithm_family := get_component_algorithm_family_or_empty(component)
    some known_family in CMAC_MAC_ALGORITHM_FAMILIES
    algorithm_family == lower(known_family)
} else if {
    is_mac_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "cmac")
}

# This is not defined in the CycloneDX specification
is_cbcmac_scheme(component) if {
    is_mac_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in CBC_MAC_ALGORITHM_OID_VALUES
} else if {
    is_mac_primitive(component)
    name := get_component_name_or_empty(component)
    normalized_name := normalize_crypto_identifier(name)
    contains(normalized_name, "cbcmac")
}

is_agreed_hmac_scheme(component) if {
    is_hmac_sha1_scheme(component) 
    is_legacy_marker_active(HMAC_SHA1_LEGACY_MARKER)
} else if {
    is_hmac_scheme(component)
    not is_hmac_sha1_scheme(component)
}

is_agreed_kmac_scheme(component) if {
    is_kmac_scheme(component)
}

is_agreed_gmac_scheme(component) if {
    is_gmac_scheme(component)
}

is_agreed_cmac_scheme(component) if {
    is_cmac_scheme(component)
}

is_agreed_cbcmac_scheme(component) if {
    is_cbcmac_scheme(component)
}

is_agreed_mac_scheme(component) if {
    is_agreed_hmac_scheme(component) 
} else if {
    is_agreed_gmac_scheme(component)
} else if {
    is_agreed_kmac_scheme(component)
} else if {
    is_agreed_cmac_scheme(component)
} else if {
    is_agreed_cbcmac_scheme(component)
}

is_mac_output_size_above_quantum_sensitive_threshold(component) if {
    is_mac_primitive(component)
    get_component_parameter_set_identifier_to_number_or_negative_one(component) >= MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_MACS
}


is_hmac_or_kmac_scheme(component) if {
    is_agreed_hmac_scheme(component)
} else if {
    is_agreed_kmac_scheme(component)
}

# Detect a possible encryption/MAC composition using source-code
# proximity.
#
# Conditions:
# 1. One component is a symmetric encryption primitive.
# 2. The other component is a MAC primitive.
# 3. Both have occurrences within 15 lines in the same file.
#
# Example:
#   crypto.py:20 -> AES-CBC
#   crypto.py:27 -> HMAC-SHA256
#
# This may indicate:
#   - MAC-then-Encrypt
#   - Encrypt-and-MAC
#   - Encrypt-then-MAC
#
# The actual construction cannot be determined from proximity.
is_possible_mac_encryption_composition(component_a, component_b) if {
    is_symmetric_encryption_scheme(component_a)
    is_mac_primitive(component_b)

    components_share_evidence_window(
        [component_a, component_b],
        15
    )
}

TEMP_MAC_ALGORITHM_NAMES := 
    HMAC_MAC_ALGORITHM_NAMES  |
    GMAC_MAC_ALGORITHM_NAMES  |
    CMAC_MAC_ALGORITHM_NAMES  |
    CBC_MAC_ALGORITHM_NAMES   |
    KMAC_MAC_ALGORITHM_NAMES  

AGREED_MAC_ALGORITHM_NAMES := names if {
    is_legacy_marker_active(HMAC_SHA1_LEGACY_MARKER)
    
    names := TEMP_MAC_ALGORITHM_NAMES | HMAC_SHA1_ALGORITHM_NAMES
} else := TEMP_MAC_ALGORITHM_NAMES
