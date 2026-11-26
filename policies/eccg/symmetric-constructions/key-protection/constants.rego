package cbom.eccg.symmetric_constructions.key_protection.constants

import data.cbom.eccg.oid_constants.NO_OID

#
# Sources:
# - https://www.rfc-editor.org/rfc/rfc5297
# - https://www.iana.org/assignments/smi-numbers
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX:
# AES[-(128|192|256)]-SIV (ae)
# ============================================================

SIV_KEY_PROTECTION_SCHEME_NAMES := {
    "SIV",
    "AES-SIV",
    "SIV-AES",
    "AES-128-SIV",
    "AES-192-SIV",
    "AES-256-SIV",
    "AES-SIV-CMAC",
    "AES-SIV-CMAC-AEAD-256",
    "AES-SIV-CMAC-AEAD-384",
    "AES-SIV-CMAC-AEAD-512",
    "AES-SIV-CMAC-WRAP-256",
    "AES-SIV-CMAC-WRAP-384",
    "AES-SIV-CMAC-WRAP-512",
}

SIV_KEY_PROTECTION_SCHEME_FAMILIES := {
    "AES",
}

SIV_KEY_PROTECTION_SCHEME_OIDS := {
    # Authenticated encryption variants
    "AES-SIV-CMAC-AEAD-256": "1.2.840.113549.1.9.16.3.22",
    "AES-SIV-CMAC-AEAD-384": "1.2.840.113549.1.9.16.3.23",
    "AES-SIV-CMAC-AEAD-512": "1.2.840.113549.1.9.16.3.24",

    # Key wrapping variants
    "AES-SIV-CMAC-WRAP-256": "1.2.840.113549.1.9.16.3.25",
    "AES-SIV-CMAC-WRAP-384": "1.2.840.113549.1.9.16.3.26",
    "AES-SIV-CMAC-WRAP-512": "1.2.840.113549.1.9.16.3.27",
}

SIV_KEY_PROTECTION_SCHEME_OID_VALUES := {
    oid | oid := SIV_KEY_PROTECTION_SCHEME_OIDS[_]
}

#
# Sources:
# - https://www.rfc-editor.org/rfc/rfc8452
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX:
# AES[-(128|192|256)]-GCM-SIV[-{tagLength}][-{ivLength}] (ae)
#
# RFC 8452 standardizes AES-128-GCM-SIV and AES-256-GCM-SIV.
# ============================================================

AES_GCM_SIV_AE_ALGORITHM_NAMES := {
    "AES-GCM-SIV",
    "AES-128-GCM-SIV",
    "AES-256-GCM-SIV",
}

AES_GCM_SIV_AE_ALGORITHM_FAMILIES := {
    "AES",
}

# No OIDs verified from RFC 8452 or the IANA AEAD registry.
AES_GCM_SIV_AE_ALGORITHM_OIDS := {
    "AES-GCM-SIV": NO_OID,
    "AES-128-GCM-SIV": NO_OID,
    "AES-256-GCM-SIV": NO_OID,
}

AES_GCM_SIV_AE_ALGORITHM_OID_VALUES := {
    oid | oid := AES_GCM_SIV_AE_ALGORITHM_OIDS[_]
}

#
# Sources:
# - https://doi.org/10.6028/NIST.SP.800-38F
# - https://www.rfc-editor.org/rfc/rfc3394
# - https://www.rfc-editor.org/rfc/rfc5649
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX:
# AES[-(128|192|256)][-(KW|KWP)] (key-wrap)
# ============================================================

AES_KEYWRAP_KEY_PROTECTION_SCHEME_NAMES := {
    "AES-KW",
    "AES-KWP",
    "AES-KeyWrap",
    "AES-KeyWrapWithPadding",
    "AES-128-KW",
    "AES-192-KW",
    "AES-256-KW",
    "AES-128-KWP",
    "AES-192-KWP",
    "AES-256-KWP",
    "AES-128-WRAP",
    "AES-192-WRAP",
    "AES-256-WRAP",
    "AES-128-WRAP-PAD",
    "AES-192-WRAP-PAD",
    "AES-256-WRAP-PAD",
}

AES_KEYWRAP_KEY_PROTECTION_SCHEME_FAMILIES := {
    "AES",
}

AES_KEYWRAP_KEY_PROTECTION_SCHEME_OIDS := {
    # AES-KW
    "AES-128-KW": "2.16.840.1.101.3.4.1.5",
    "AES-192-KW": "2.16.840.1.101.3.4.1.25",
    "AES-256-KW": "2.16.840.1.101.3.4.1.45",

    # AES-KWP
    "AES-128-KWP": "2.16.840.1.101.3.4.1.8",
    "AES-192-KWP": "2.16.840.1.101.3.4.1.28",
    "AES-256-KWP": "2.16.840.1.101.3.4.1.48",
}

AES_KEYWRAP_KEY_PROTECTION_SCHEME_OID_VALUES := {
    oid | oid := AES_KEYWRAP_KEY_PROTECTION_SCHEME_OIDS[_]
}
