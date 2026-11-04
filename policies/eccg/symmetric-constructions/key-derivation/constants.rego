package cbom.eccg.symmetric_constructions.key_derivation.constants

import data.cbom.eccg.oid_constants.NO_OID

#
# Sources:
# - https://doi.org/10.6028/NIST.SP.800-56Ar3
# - https://doi.org/10.6028/NIST.SP.800-56Br2
# - https://doi.org/10.6028/NIST.SP.800-56Cr2
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX family: SP800-56C
# CycloneDX primitive: kdf
# ============================================================

# ============================================================
# NIST SP 800-56A/B/C Key Derivation
# ============================================================

NIST_SP800_56_KDF_NAMES := {
    # SP 800-56A
    "SP800-56A",
    "SP800-56A-KDF",
    "NIST-SP800-56A",

    # SP 800-56B
    "SP800-56B",
    "SP800-56B-KDF",
    "NIST-SP800-56B",

    # SP 800-56C
    "SP800-56C",
    "SP800-56C-KDF",
    "NIST-SP800-56C",
    "NIST-SP800-56-KDF",

    # One-step KDF
    "SP800_56C_OneStep",
    "SP800-56C-OneStep",
    "SP800-56C-OneStep-KDF",

    # Two-step KDF
    "SP800_56C_TwoStep_CounterKDF",
    "SP800_56C_TwoStep_FeedbackKDF",
    "SP800_56C_TwoStep_DoublePipelineKDF",

    # Common descriptive names
    "SP800-56C-TwoStep",
    "SP800-56C-Extraction-Expansion",
}

NIST_SP800_56_KDF_FAMILIES := {
    "SP800-56A",
    "SP800-56B",
    "SP800-56C",
}

# No standalone general-purpose KDF OIDs verified
NIST_SP800_56_KDF_OIDS := {
    # SP 800-56A
    "SP800-56A": NO_OID,
    "SP800-56A-KDF": NO_OID,
    "NIST-SP800-56A": NO_OID,

    # SP 800-56B
    "SP800-56B": NO_OID,
    "SP800-56B-KDF": NO_OID,
    "NIST-SP800-56B": NO_OID,

    # SP 800-56C
    "SP800-56C": NO_OID,
    "SP800-56C-KDF": NO_OID,
    "NIST-SP800-56C": NO_OID,
    "NIST-SP800-56-KDF": NO_OID,

    # One-step KDF
    "SP800_56C_OneStep": NO_OID,
    "SP800-56C-OneStep": NO_OID,
    "SP800-56C-OneStep-KDF": NO_OID,

    # Two-step KDF
    "SP800_56C_TwoStep_CounterKDF": NO_OID,
    "SP800_56C_TwoStep_FeedbackKDF": NO_OID,
    "SP800_56C_TwoStep_DoublePipelineKDF": NO_OID,

    # Common descriptive names
    "SP800-56C-TwoStep": NO_OID,
    "SP800-56C-Extraction-Expansion": NO_OID,
}

NIST_SP800_56_KDF_OID_VALUES := {
    oid | oid := NIST_SP800_56_KDF_OIDS[_]
}

#
# Sources:
# - ANSI X9.63
# - SEC 1, Section 3.6.1
# - RFC 8755
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX family: ANSI-KDF
# CycloneDX primitive: kdf
# ============================================================

ANSI_X963_KDF_NAMES := {
    "ANSI-KDF-X9.63",
    "ANSI-X9.63-KDF",
    "ANSI-X9.63",
    "X9.63-KDF",
    "X963-KDF",
    "X963KDF",
    "X9.63KDF",
    "ANSI-X963-KDF",

    # Hash variants
    "ANSI-KDF-X9.63-SHA-1",
    "ANSI-KDF-X9.63-SHA-224",
    "ANSI-KDF-X9.63-SHA-256",
    "ANSI-KDF-X9.63-SHA-384",
    "ANSI-KDF-X9.63-SHA-512",

    # Common implementation aliases
    "X963KDF-SHA256",
    "X963KDF-SHA384",
    "X963KDF-SHA512",
}

ANSI_X963_KDF_FAMILIES := {
    "ANSI-KDF",
}

# No standalone ANSI X9.63 KDF OID verified.
ANSI_X963_KDF_OIDS := {
    "ANSI-KDF-X9.63": NO_OID,
    "ANSI-X9.63-KDF": NO_OID,
    "ANSI-X9.63": NO_OID,
    "X9.63-KDF": NO_OID,
    "X963-KDF": NO_OID,
    "X963KDF": NO_OID,
    "X9.63KDF": NO_OID,
    "ANSI-X963-KDF": NO_OID,

    # Hash variants
    "ANSI-KDF-X9.63-SHA-1": NO_OID,
    "ANSI-KDF-X9.63-SHA-224": NO_OID,
    "ANSI-KDF-X9.63-SHA-256": NO_OID,
    "ANSI-KDF-X9.63-SHA-384": NO_OID,
    "ANSI-KDF-X9.63-SHA-512": NO_OID,

    # Common implementation aliases
    "X963KDF-SHA256": NO_OID,
    "X963KDF-SHA384": NO_OID,
    "X963KDF-SHA512": NO_OID,

}

ANSI_X963_KDF_OID_VALUES := {
    oid | oid := ANSI_X963_KDF_OIDS[_]
}

#
# Sources:
# - https://www.rfc-editor.org/rfc/rfc8018
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX family: PBKDF2
# CycloneDX primitive: kdf
# ============================================================

PBKDF2_KDF_NAMES := {
    "PBKDF2",
    "PKCS5-PBKDF2",
    "PKCS5_PBKDF2_HMAC",

    # Common PRF variants
    "PBKDF2-HMAC-SHA1",
    "PBKDF2-HMAC-SHA224",
    "PBKDF2-HMAC-SHA256",
    "PBKDF2-HMAC-SHA384",
    "PBKDF2-HMAC-SHA512",
    "PBKDF2-HMAC-SHA512-224",
    "PBKDF2-HMAC-SHA512-256",

    # Additional naming conventions
    "PBKDF2-SHA1",
    "PBKDF2-SHA256",
    "PBKDF2-SHA384",
    "PBKDF2-SHA512",
}

PBKDF2_KDF_FAMILIES := {
    "PBKDF2",
}

PBKDF2_KDF_OIDS := {
    "PBKDF2": "1.2.840.113549.1.5.12",
}

PBKDF2_KDF_OID_VALUES := {
    oid | oid := PBKDF2_KDF_OIDS[_]
}

# Sources:
# - https://www.rfc-editor.org/rfc/rfc5869
# - https://www.rfc-editor.org/rfc/rfc8619
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX family: HKDF
# CycloneDX primitive: kdf
# ============================================================

HKDF_KDF_NAMES := {
    "HKDF",
    "HMAC-based-KDF",
    "HMAC-based-Extract-and-Expand-KDF",

    # Hash variants
    "HKDF-SHA1",
    "HKDF-SHA224",
    "HKDF-SHA256",
    "HKDF-SHA384",
    "HKDF-SHA512",

    # Common aliases
    "HKDF-SHA-256",
    "HKDF-SHA-384",
    "HKDF-SHA-512",
    "HKDF-HMAC-SHA256",
    "HKDF-HMAC-SHA384",
    "HKDF-HMAC-SHA512",
}

HKDF_KDF_FAMILIES := {
    "HKDF",
}

HKDF_KDF_OIDS := {
    "HKDF-SHA256": "1.2.840.113549.1.9.16.3.28",
    "HKDF-SHA384": "1.2.840.113549.1.9.16.3.29",
    "HKDF-SHA512": "1.2.840.113549.1.9.16.3.30",
}

HKDF_KDF_OID_VALUES := {
    oid | oid := HKDF_KDF_OIDS[_]
}
