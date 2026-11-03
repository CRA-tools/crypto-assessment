package cbom.eccg.symmetric_constructions.password_protection.helpers

import data.cbom.eccg.general_helpers.matches_crypto_identifier

import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty

import data.cbom.eccg.classifying_helpers.is_kdf_primitive
import data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_pbkdf2_scheme as is_pbkdf2_kdf_scheme

import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_PASSWORD_HASHING_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_PASSWORD_HASHING_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.password_protection.constants.PBKDF2_PASSWORD_HASHING_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_PASSWORD_HASHING_SCHEME_NAMES

password_protection_scheme_metadata(_) := {
}

is_argon2id_scheme(component) if {
    is_kdf_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in ARGON2ID_PASSWORD_HASHING_SCHEME_OID_VALUES
} else if {
    is_kdf_primitive(component)
    family := get_component_algorithm_family_or_empty(component)
    # Generic Argon2 also includes Argon2i and Argon2d; require the id variant.
    matches_crypto_identifier(family, ARGON2ID_PASSWORD_HASHING_SCHEME_NAMES)
} else if {
    is_kdf_primitive(component)
    name := get_component_name_or_empty(component)
    matches_crypto_identifier(name, ARGON2ID_PASSWORD_HASHING_SCHEME_NAMES)
} else if {
    is_kdf_primitive(component)
    name := get_component_name_or_empty(component)
    # CycloneDX may append numeric memory, pass, parallelism, and length values.
    regex.match(`^argon2[-_ ]?id(-[0-9]+){1,7}$`, name)
}

is_pbkdf2_scheme(component) if {
    is_pbkdf2_kdf_scheme(component)
}

is_agreed_password_protection_scheme(component) if {
    is_argon2id_scheme(component)
} else if {
    is_pbkdf2_scheme(component)
}

AGREED_PASSWORD_HASHING_SCHEMES := {
    PBKDF2_PASSWORD_HASHING_SCHEME_FAMILIES |
    ARGON2ID_PASSWORD_HASHING_SCHEME_FAMILIES
}
