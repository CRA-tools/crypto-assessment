package cbom.eccg.symmetric_atomic_primitives.hashes.helpers

import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty

import data.cbom.eccg.classifying_helpers.is_hash_primitive

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.symmetric_atomic_primitives.hashes.constants.SHA2_HASH_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_atomic_primitives.hashes.constants.SHA3_HASH_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_atomic_primitives.hashes.constants.SHA2_HASH_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.hashes.constants.SHA3_HASH_ALGORITHM_OIDS
import data.cbom.eccg.symmetric_atomic_primitives.hashes.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH

hash_primitive_metadata(component) := {
    "hashBits": get_component_parameter_set_identifier_to_number_or_negative_one(component),
    "minimumRecommendedHashBitsForQuantumSensitiveContext": MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH,
}

is_sha256(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid == SHA2_HASH_ALGORITHM_OIDS["SHA-256"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(get_component_name_or_empty(component))
    normalized_name == "sha256"
}


is_sha384(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid == SHA2_HASH_ALGORITHM_OIDS["SHA-384"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(get_component_name_or_empty(component))
    normalized_name == "sha384"
}

is_sha512(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid == SHA2_HASH_ALGORITHM_OIDS["SHA-512"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(get_component_name_or_empty(component))
    normalized_name == "sha512"
}

is_sha512_256(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid == SHA2_HASH_ALGORITHM_OIDS["SHA-512/256"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(get_component_name_or_empty(component))
    normalized_name == "sha512256"
}

is_sha3_256(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid == SHA3_HASH_ALGORITHM_OIDS["SHA3-256"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(get_component_name_or_empty(component))
    normalized_name == "sha3256"
}

is_sha3_384(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid == SHA3_HASH_ALGORITHM_OIDS["SHA3-384"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(get_component_name_or_empty(component))
    normalized_name == "sha3384"
}

is_sha3_512(component) if {
    is_hash_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid == SHA3_HASH_ALGORITHM_OIDS["SHA3-512"]
} else if {
    is_hash_primitive(component)
    normalized_name := normalize_crypto_identifier(get_component_name_or_empty(component))
    normalized_name == "sha3512"
}

is_agreed_hash_component(component) if {
    is_sha256(component)
} else if {
    is_sha384(component)
} else if {
    is_sha512(component)
} else if {
    is_sha512_256(component)
} else if {
    is_sha3_256(component)
} else if {
    is_sha3_384(component)
} else if {
    is_sha3_512(component)
}

is_hash_output_size_above_quantum_sensitive_threshold(component) if {
    is_hash_primitive(component)
    get_component_parameter_set_identifier_to_number_or_negative_one(component) >= MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH
}

AGREED_HASH_ALGORITHM_NAMES :=
    SHA2_HASH_ALGORITHM_NAMES |
    SHA3_HASH_ALGORITHM_NAMES 
