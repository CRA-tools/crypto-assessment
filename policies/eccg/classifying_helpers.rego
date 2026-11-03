package cbom.eccg.classifying_helpers

import data.cbom.eccg.getter_helpers.get_component_asset_type_or_empty
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty   
import data.cbom.eccg.getter_helpers.get_component_mode_or_empty
import data.cbom.eccg.getter_helpers.get_component_crypto_function_or_empty
import data.cbom.eccg.getter_helpers.get_related_crypto_material_type_or_empty

import data.cbom.eccg.relationship_helpers.depends_on_component
import data.cbom.eccg.relationship_helpers.components_share_evidence_location_and_line
import data.cbom.eccg.relationship_helpers.components_share_evidence_location_within_lines


allowed_severities := {"warning", "info", "low", "medium", "high", "critical", "error"}

is_drbg_primitive(component) if {
    get_component_asset_type_or_empty(component) in {"algorithm", "related-crypto-material"}
    get_component_primitive_or_empty(component) == "drbg"
}

is_valid_severity(sev) if {
    allowed_severities[sev]
}

is_mac_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "mac"

}

is_stream_cipher_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "stream-cipher"
}

is_hash_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "hash"
}

is_xof_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "xof"
}

is_block_cipher_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "block-cipher"
}

is_ae_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "ae"
}

is_block_cipher_or_ae_primitive(component) if {
    is_block_cipher_primitive(component)
} else if {
    is_ae_primitive(component)
}


is_kdf_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "kdf"
}

is_pke_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-properties"]

    get_component_primitive_or_empty(component) == "pke"
}

is_signature_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-properties"]

    get_component_primitive_or_empty(component) == "signature"
}

is_key_wrap_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "key-wrap"
}

is_key_wrap_or_ae_primitive(component) if {
    is_key_wrap_primitive(component)
} else if {
    is_ae_primitive(component)
}

is_gcm_primitive(component) if {
    is_ae_primitive(component)
    get_component_mode_or_empty(component) == "gcm"
}

is_ccm_primitive(component) if {
    is_ae_primitive(component)
    get_component_mode_or_empty(component) == "ccm"
}

is_password_hashing_primitive(component) if {
    is_kdf_primitive(component)
}

is_gcm_or_ccm_primitive(component) if {
    is_gcm_primitive(component)
} else if {
    is_ccm_primitive(component)
}

is_stream_cipher_or_block_cipher_primitive(component) if {
    is_block_cipher_primitive(component)
} else if {
    is_stream_cipher_primitive(component)
}

is_combiner_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "combiner"

}

is_public_key_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "pke"
}

is_kem_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "kem"
}

is_key_agreement_primitive(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    get_component_primitive_or_empty(component) == "key-agree"
}

is_public_key_eccg_primitive(component) if {
    is_pke_primitive(component)
} else if {
    is_signature_primitive(component)
} else if {
    is_kem_primitive(component)
}

# Both key encapsulation mechanisms and key agreement mechanisms can be used for key establishment
# Key establishment can be achieved through:
# - Key agreement (e.g., ECDH/X25519): Alice and Bob exchange public keys
#   and independently derive the same shared secret.
# - Key encapsulation (e.g., ML-KEM): Alice encapsulates a shared secret
#   using Bob's public key and sends the ciphertext. Bob decapsulates
#   it using his private key to recover the same shared secret.
# Both mechanisms establish shared keying material.
is_key_establishment_primitive(component) if {
    is_key_agreement_primitive(component)
} else if {
    is_kem_primitive(component)
}


is_sign_crypto_function(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    "sign" in get_component_crypto_function_or_empty(component)
}

is_verify_crypto_function(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    "verify" in get_component_crypto_function_or_empty(component)
}


#
# ---------------------------------------------------------
# Helper: is_symmetric_encryption_scheme
#
# A symmetric encryption scheme uses secret-key cryptography
# to protect data, with encryption and decryption relying
# on the same shared secret key.
#
# In this policy, symmetric encryption encompasses two
# cryptographic primitive categories:
#
# - Block ciphers: Provide the underlying transformation
#   used to achieve confidentiality. A block cipher alone
#   is not a complete encryption scheme; an appropriate
#   mode of operation is also required.
#
# - Authenticated encryption (AE): Provides confidentiality
#   together with message integrity and authenticity.
#   Examples include AES-GCM and AES-CCM.
#
# This classification groups both primitive categories
# under symmetric encryption for ECCG policy evaluation.
# It does not imply that every algorithm or mode in these
# categories is secure or approved by the ECCG.
#
# ---------------------------------------------------------
#
is_symmetric_encryption_scheme(component) if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    is_block_cipher_primitive(component)
} else if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    is_ae_primitive(component)
} else if {
    asset_type := get_component_asset_type_or_empty(component)
    asset_type in ["algorithm", "related-crypto-material"]
    is_stream_cipher_primitive(component)
}

#
# ---------------------------------------------------------
# Helper: is_possible_encryption_mac_composition
#
# Heuristic detection of a possible composed authenticated-
# encryption construction.
#
# Returns true when:
# - one component is a symmetric encryption scheme, and
# - another component is a MAC scheme, and
# - both share the same source location and line or more weakly the same source location.
#
# This represents a strong heuristic that both operations may
# belong to the same logical construction (e.g., Encrypt-then-MAC,
# MAC-then-Encrypt, or Encrypt-and-MAC).
#
# Limitations:
# - This helper does NOT determine the order of operations.
# - It does NOT distinguish between different composition patterns.
# - It relies on CBOM evidence granularity; if extraction does not
#   align components to the same line, this may produce false negatives.
#
# Intended use:
# - trigger higher-level findings indicating possible composed AE
#   constructions where exact classification is not possible.
# ---------------------------------------------------------
#
is_possible_encryption_mac_composition(enc_component, mac_component) if {
    is_symmetric_encryption_scheme(enc_component)
    is_mac_primitive(mac_component)
    _has_encryption_mac_relationship(enc_component, mac_component)
}

_has_encryption_mac_relationship(enc_component, mac_component) if {
    depends_on_component(enc_component, mac_component)
}

_has_encryption_mac_relationship(enc_component, mac_component) if {
    depends_on_component(mac_component, enc_component)
}

_has_encryption_mac_relationship(enc_component, mac_component) if {
    components_share_evidence_location_and_line(enc_component, mac_component)
}

_has_encryption_mac_relationship(enc_component, mac_component) if {
    components_share_evidence_location_within_lines(enc_component, mac_component, 5)
}


#
# True when the component represents related cryptographic material.
#
# This identifies CBOM components where:
#
#   cryptoProperties.assetType == "related-crypto-material"
#
# These components are not algorithms themselves. They represent material
# associated with cryptographic algorithms, such as keys, signatures,
# ciphertexts, digests, or IVs.
#
is_related_crypto_material(component) if {
    get_component_asset_type_or_empty(component) == "related-crypto-material"
}

#
# True when the component represents private key material.
#
# This identifies components such as:
#
#   {
#     "cryptoProperties": {
#       "assetType": "related-crypto-material",
#       "relatedCryptoMaterialProperties": {
#         "type": "private-key"
#       }
#     }
#   }
#
# This is useful for flagging generated, embedded, stored, or otherwise
# exposed asymmetric private keys.
#
is_private_key_material(component) if {
    is_related_crypto_material(component)
    get_related_crypto_material_type_or_empty(component) == "private-key"
}

#
# True when the component represents public key material.
#
# This identifies components such as:
#
#   {
#     "cryptoProperties": {
#       "assetType": "related-crypto-material",
#       "relatedCryptoMaterialProperties": {
#         "type": "public-key"
#       }
#     }
#   }
#
# Public keys are not confidential, but they may still need policy review for
# trust, lifecycle, algorithm family, and key-size requirements.
#
is_public_key_material(component) if {
    is_related_crypto_material(component)
    get_related_crypto_material_type_or_empty(component) == "public-key"
}

#
# ---------------------------------------------------------
# Helper: is_asymmetric_algorithm
#
# Purpose:
# Identify asymmetric cryptographic algorithm components in a CBOM.
#
# Detection strategy:
# This helper treats a component as asymmetric if it is modeled as
# an algorithm and satisfies at least one of the following conditions:
#
# 1. The algorithm primitive is public-key encryption:
#      primitive == "pke"
#
# 2. The algorithm primitive is key agreement:
#      primitive == "key-agree"
#
# 3. The algorithm primitive is key encapsulation:
#      primitive == "kem"
#
# 4. The algorithm primitive is signature, or it exposes signature functions:
#      primitive == "signature"
#      cryptoFunctions contains "sign" or "verify"
#
# Rationale:
# CycloneDX / CBOM representations may not encode all asymmetric
# algorithms using the same primitive value.
#
# For example:
# - RSA encryption may appear as primitive = "pke"
# - ECDH / FFDHE / X25519 may appear as primitive = "key-agree"
# - ML-KEM / other KEMs may appear as primitive = "kem"
# - ECDSA / EdDSA / RSA signatures may appear as primitive = "signature"
#
# Therefore, checking only primitive == "pke" would miss many
# asymmetric algorithms, especially key-agreement and signature schemes.
#
# Intended use:
# - Shared precondition for asymmetric primitive rules.
# - Useful before applying RSA, FF-DLOG, EC-DLOG, signature, or
#   key-agreement specific classification logic.
#
# Notes:
# - This helper does not classify the exact asymmetric family.
# - It only determines that the component belongs to the broader
#   asymmetric/public-key cryptography space.
# - Family-specific helpers such as is_rsa_primitive(),
#   is_ffdlog_primitive(), and is_ecdlog_primitive() should perform
#   more precise matching.
# ---------------------------------------------------------
#
is_asymmetric_algorithm(component) if {
    is_pke_primitive(component)
} else if {
    is_key_agreement_primitive(component)
} else if {
    is_kem_primitive(component)
} else if {
    is_signature_primitive(component)
} else if {
    is_sign_crypto_function(component)
} else if {
    is_verify_crypto_function(component)
}
