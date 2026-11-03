package cbom.eccg.symmetric_constructions.key_protection.helpers 

import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty
import data.cbom.eccg.getter_helpers.get_component_mode_or_empty

import data.cbom.eccg.general_helpers.matches_crypto_identifier
import data.cbom.eccg.general_helpers.matches_aes_construction_name
import data.cbom.eccg.general_helpers.normalize_crypto_identifier

import data.cbom.eccg.classifying_helpers.is_key_wrap_or_ae_primitive

import data.cbom.eccg.symmetric_constructions.key_protection.constants.SIV_KEY_PROTECTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_protection.constants.AES_GCM_SIV_AE_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_protection.constants.AES_KEYWRAP_KEY_PROTECTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.key_protection.constants.SIV_KEY_PROTECTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.key_protection.constants.AES_GCM_SIV_AE_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.key_protection.constants.AES_KEYWRAP_KEY_PROTECTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.key_protection.constants.AES_KEYWRAP_KEY_PROTECTION_SCHEME_FAMILIES

key_protection_scheme_metadata(component) := {
    "mode": get_component_mode_or_empty(component),
    "primitive": get_component_primitive_or_empty(component),
}

is_siv_scheme(component) if {
    is_key_wrap_or_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in SIV_KEY_PROTECTION_SCHEME_OID_VALUES
} else if {
    is_key_wrap_or_ae_primitive(component)
    matches_crypto_identifier(get_component_algorithm_family_or_empty(component), SIV_KEY_PROTECTION_SCHEME_NAMES)
} else if {
    is_key_wrap_or_ae_primitive(component)
    name := get_component_name_or_empty(component)
    matches_crypto_identifier(name, SIV_KEY_PROTECTION_SCHEME_NAMES)
} else if {
    is_key_wrap_or_ae_primitive(component)
    matches_aes_construction_name(get_component_name_or_empty(component), "siv")
}

is_gcm_siv_scheme(component) if {
    is_key_wrap_or_ae_primitive(component)
    get_component_oid_or_empty(component) in AES_GCM_SIV_AE_ALGORITHM_OID_VALUES
} else if {
    is_key_wrap_or_ae_primitive(component)
    matches_crypto_identifier(get_component_name_or_empty(component), AES_GCM_SIV_AE_ALGORITHM_NAMES)
} else if {
    is_key_wrap_or_ae_primitive(component)
    matches_aes_construction_name(get_component_name_or_empty(component), "gcm[-_ ]?siv")
}

is_aeskw_scheme(component) if {
    is_key_wrap_or_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in AES_KEYWRAP_KEY_PROTECTION_SCHEME_OID_VALUES
} else if {
    is_key_wrap_or_ae_primitive(component)
    matches_crypto_identifier(get_component_algorithm_family_or_empty(component), AES_KEYWRAP_KEY_PROTECTION_SCHEME_FAMILIES)
    matches_aes_construction_name(get_component_name_or_empty(component), "kwp?")
} else if {
    is_key_wrap_or_ae_primitive(component)
    name := get_component_name_or_empty(component)
    matches_crypto_identifier(name, AES_KEYWRAP_KEY_PROTECTION_SCHEME_NAMES)
} else if {
    is_key_wrap_or_ae_primitive(component)
    name := get_component_name_or_empty(component)
    contains(normalize_crypto_identifier(name), "aes")
    matches_aes_construction_name(name, "kwp?|key[-_ ]?wrap(with[-_ ]?padding)?|wrap([-_ ]pad)?")
} else if {
    is_key_wrap_or_ae_primitive(component)
    name := get_component_name_or_empty(component)
    regex.match(`^aes([-_ ]?[0-9]+)?[-_ ]wrap[-_ ]pkcs7$`, name)
}

is_agreed_key_protection_scheme(component) if {
    is_siv_scheme(component)
} else if {
    is_aeskw_scheme(component)
}
