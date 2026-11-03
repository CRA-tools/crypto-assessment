package cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers

import data.cbom.eccg.general_helpers.matches_aes_construction_name

import data.cbom.eccg.classifying_helpers.is_block_cipher_primitive
import data.cbom.eccg.classifying_helpers.is_ae_primitive
import data.cbom.eccg.classifying_helpers.is_mac_primitive
import data.cbom.eccg.classifying_helpers.is_hash_primitive
import data.cbom.eccg.classifying_helpers.is_stream_cipher_or_block_cipher_primitive

import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty
import data.cbom.eccg.getter_helpers.get_component_mode_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_bom_ref_or_empty


import data.cbom.eccg.relationship_helpers.components_share_evidence_window

import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CTR_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CTR_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.OFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.OFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.XTS_DISK_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.ECB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.ECB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_ESSIV_DISK_ENCRYPTION_SCHEME_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_ESSIV_DISK_ENCRYPTION_SCHEME_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CCM_AE_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CCM_AE_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_AE_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_AE_ALGORITHM_FAMILIES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.EAX_AE_ALGORITHM_OID_VALUES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_ESSIV_DISK_ENCRYPTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CBC_SYMMETRIC_ENCRYPTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CCM_AE_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CTR_SYMMETRIC_ENCRYPTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.CFB_SYMMETRIC_ENCRYPTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.EAX_AE_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.OFB_SYMMETRIC_ENCRYPTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_AE_ALGORITHM_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.XTS_DISK_ENCRYPTION_SCHEME_NAMES

import data.cbom.eccg.symmetric_constructions.key_protection.helpers.is_agreed_key_protection_scheme
import data.cbom.eccg.symmetric_constructions.key_protection.helpers.is_gcm_siv_scheme


symmetric_encryption_scheme_metadata(component) := {
    "primitive": get_component_primitive_or_empty(component), 
    "mode": get_component_mode_or_empty(component),
}

is_ecb_scheme(component) if {
    is_stream_cipher_or_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in ECB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    some known_family in ECB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    family == lower(known_family)
    mode := get_component_mode_or_empty(component)
    mode == "ecb"
} else if {
    is_stream_cipher_or_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "ecb")
}

is_ctr_scheme(component) if {
    is_stream_cipher_or_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CTR_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    some known_family in CTR_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    family == lower(known_family)
    mode := get_component_mode_or_empty(component)
    mode == "ctr"
} else if {
    is_stream_cipher_or_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "ctr")
}

is_ofb_scheme(component) if {
    is_stream_cipher_or_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in OFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    some known_family in OFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    family == lower(known_family)
    mode := get_component_mode_or_empty(component)
    mode == "ofb"
} else if {
    is_stream_cipher_or_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "ofb")
}

is_cbc_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CBC_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    some known_family in CBC_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    family == lower(known_family)
    mode := get_component_mode_or_empty(component)
    mode == "cbc"
    not matches_aes_construction_name(get_component_name_or_empty(component), "cbc[-_ ]?(cs[123]?|essiv(:sha256)?)")
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "cbc")
}

# there is no supported mode for cbs-cs
is_cbc_cs_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "cbc[-_ ]?cs[123]?")
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "cts")
}


is_cfb_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    some known_family in CFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES
    family == lower(known_family)
    mode := get_component_mode_or_empty(component)
    mode == "cfb"
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "cfb(1|8|64|128)?")
}

is_agreed_symmetric_encryption_scheme(component) if {
    is_ctr_scheme(component) 
} else if {
    is_ofb_scheme(component)
} else if {
    is_cbc_scheme(component)
} else if {
    is_cbc_cs_scheme(component)
} else if {
    is_cfb_scheme(component)
}

is_agreed_stream_symmetric_encryption_scheme(component) if {
    is_ctr_scheme(component)
} else if {
    is_ofb_scheme(component)
}

is_agreed_padding_sensitive_symmetric_encryption_scheme(component) if {
    is_cbc_scheme(component)
} else if {
    is_cfb_scheme(component)
}

is_xts_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in XTS_DISK_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "xts")
}


is_cbc_essiv_scheme(component) if {
    is_block_cipher_primitive(component)
    oid := get_component_oid_or_empty(component)  
    oid in CBC_ESSIV_DISK_ENCRYPTION_SCHEME_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    some known_family in CBC_ESSIV_DISK_ENCRYPTION_SCHEME_FAMILIES
    family == lower(known_family)
    mode := get_component_mode_or_empty(component)
    mode == "cbc"
} else if {
    is_block_cipher_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "cbc[-_ ]?essiv(:sha256)?")
} else if {
    is_cbc_essiv_heuristic(component)
}

is_cbc_essiv_heuristic(cbc_component) if {
    # Data-encryption cipher
    is_block_cipher_primitive(cbc_component)
    get_component_mode_or_empty(cbc_component) == "cbc"

    family := get_component_algorithm_family_or_empty(cbc_component)
    family != ""

    # Hash function
    some hash in input.components
    is_hash_primitive(hash)

    # IV-generation cipher
    some iv_block_cipher in input.components
    is_block_cipher_primitive(iv_block_cipher)

    # Distinct cryptographic assets
    iv_block_cipher["bom-ref"] != cbc_component["bom-ref"]

    # Same underlying block cipher family
    family == get_component_algorithm_family_or_empty(iv_block_cipher)

    # Evidence proximity
    components_share_evidence_window(
        [hash, iv_block_cipher, cbc_component],
        15
    )
}

is_agreed_disk_encryption_scheme(component) if {
    is_xts_scheme(component)
} else if {
    is_cbc_essiv_scheme(component)
}

is_ccm_scheme(component) if {
    is_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in CCM_AE_ALGORITHM_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    some known_family in CCM_AE_ALGORITHM_FAMILIES
    family == lower(known_family)
    mode := get_component_mode_or_empty(component)
    mode == "ccm"
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "ccm"
    is_ae_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "ccm")
}

is_gcm_scheme(component) if {
    is_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in GCM_AE_ALGORITHM_OID_VALUES
} else if {
    family := get_component_algorithm_family_or_empty(component)
    some known_family in GCM_AE_ALGORITHM_FAMILIES
    family == lower(known_family)
    mode := get_component_mode_or_empty(component)
    mode == "gcm"
    not is_gcm_siv_scheme(component)
} else if {
    mode := get_component_mode_or_empty(component)
    mode == "gcm"
    is_ae_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "gcm")
}

is_eax_scheme(component) if {
    is_ae_primitive(component)
    oid := get_component_oid_or_empty(component)
    oid in EAX_AE_ALGORITHM_OID_VALUES
} else if {
    is_ae_primitive(component)
    name := get_component_name_or_empty(component)
    matches_aes_construction_name(name, "eax")
}

is_agreed_authenticated_encryption_scheme(component) if {
    is_gcm_scheme(component)
} else if {
    is_ccm_scheme(component)
} else if {
    is_eax_scheme(component)
} 
#else if {
#    #TODO heuristic for encrypt-then-mac
#    is_mac_encryption_pair(component)
#}


is_agreed_symmetric_encryption_or_authenticated_encryption_or_disk_encryption_or_key_protection_scheme(component) if {
    is_agreed_symmetric_encryption_scheme(component)
} else if {
    is_agreed_authenticated_encryption_scheme(component)
} else if {
    is_agreed_disk_encryption_scheme(component)
} else if {
    is_agreed_key_protection_scheme(component)
}


is_mac_encryption_pair(mac, encryption) if {
    is_mac_primitive(mac)
    is_stream_cipher_or_block_cipher_primitive(encryption)

    mac_bom_ref := get_component_bom_ref_or_empty(mac)
    mac_bom_ref != ""

    mac_bom_ref != get_component_bom_ref_or_empty(encryption)

    components_share_evidence_window(
        [mac, encryption],
        15
    )
}


is_agreed_symmetric_encryption_scheme_requires_unpredictable_iv(component) if {
    is_cbc_scheme(component)
} else if {
    is_cbc_cs_scheme(component)
} else if {
    is_cfb_scheme(component)
} 

is_agreed_symmetric_encryption_scheme_requires_unique_iv(component) if {
    is_ofb_scheme(component)
} else if {
    is_ctr_scheme(component)
} else if {
    is_ccm_scheme(component)
} else if {
    is_gcm_scheme(component)
} else if {
    is_eax_scheme(component)
}

get_iv_requirement_message(component) := message if {
    is_agreed_symmetric_encryption_scheme_requires_unpredictable_iv(component)

    name := get_component_name_or_empty(component)

    message := sprintf(
        "%s requires an unpredictable initialization vector (IV). Predictable IVs, including constant IVs, are not accepted.",
        [name]
    )

}  else := message if {
    is_agreed_symmetric_encryption_scheme_requires_unique_iv(component)

    name := get_component_name_or_empty(component)

    message := sprintf(
        "%s requires a unique IV or nonce for each encryption operation under the same key.",
        [name]
    )
}

AGREED_SEAS_SCHEME_NAMES := (
    # Authenticated encryption
    GCM_AE_ALGORITHM_NAMES |
    EAX_AE_ALGORITHM_NAMES |
    CCM_AE_ALGORITHM_NAMES 
)


AGREED_SYMMETRIC_ENCRYPTION_SCHEME_NAMES := (
    # Symmetric encryption
    CTR_SYMMETRIC_ENCRYPTION_SCHEME_NAMES |
    OFB_SYMMETRIC_ENCRYPTION_SCHEME_NAMES |
    CBC_SYMMETRIC_ENCRYPTION_SCHEME_NAMES |
    CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_NAMES |
    CFB_SYMMETRIC_ENCRYPTION_SCHEME_NAMES |

    # Authenticated encryption
    GCM_AE_ALGORITHM_NAMES |
    EAX_AE_ALGORITHM_NAMES |
    CCM_AE_ALGORITHM_NAMES |

    # Disk encryption
    XTS_DISK_ENCRYPTION_SCHEME_NAMES |
    CBC_ESSIV_DISK_ENCRYPTION_SCHEME_NAMES
)
