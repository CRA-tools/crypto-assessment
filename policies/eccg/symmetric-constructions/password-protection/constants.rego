package cbom.eccg.symmetric_constructions.password_protection.constants

import data.cbom.eccg.oid_constants.NO_OID
ARGON2ID_ITERATIONS_REQUIRED := 1
ARGON2ID_PARALLELISM_REQUIRED := 4
ARGON2ID_MEMORY_REQUIRED_KIB := 2097152
ARGON2ID_SALT_REQUIRED_BITS := 128
ARGON2ID_TAG_REQUIRED_BITS := 256

#
# Sources:
# - https://www.rfc-editor.org/rfc/rfc9106
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX:
# Family: Argon2
# Primitive: kdf
#
# Argon2(id|i|d)[-{memoryKiB}][-{passes}][-{parallelism}]
#           [-{saltLenBytes}][-{secretLenBytes}]
#           [-{associatedDataLenBytes}][-{tagLenBytes}]
#
# Only Argon2id is agreed in ECCG Section 3.8.
# ============================================================

ARGON2ID_PASSWORD_HASHING_SCHEME_NAMES := {
    "Argon2id",
    "Argon2-id",
    "ARGON2ID",
    "argon2id",
    "Argon2id-v19",
}

ARGON2ID_PASSWORD_HASHING_SCHEME_FAMILIES := {
    "Argon2",
}

# No Argon2id OID verified in RFC 9106.
ARGON2ID_PASSWORD_HASHING_SCHEME_OIDS := {
    "Argon2id": NO_OID,
    "Argon2-id": NO_OID,
    "ARGON2ID": NO_OID,
    "argon2id": NO_OID,
    "Argon2id-v19": NO_OID,
}

ARGON2ID_PASSWORD_HASHING_SCHEME_OID_VALUES := {
    oid | oid := ARGON2ID_PASSWORD_HASHING_SCHEME_OIDS[_]
}

#
# Sources:
# - https://www.rfc-editor.org/rfc/rfc8018
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX:
# Family: PBKDF2
# Primitive: kdf
#
# PBKDF2[-{hashAlgorithm}][-{iterations}][-{dkLen}]
#
# OID: 1.2.840.113549.1.5.12
# ============================================================

PBKDF2_PASSWORD_HASHING_SCHEME_NAMES := {
    "PBKDF2",
    "PKCS5-PBKDF2",
    "PKCS5_PBKDF2_HMAC",

    # Hash variants
    "PBKDF2-SHA1",
    "PBKDF2-SHA224",
    "PBKDF2-SHA256",
    "PBKDF2-SHA384",
    "PBKDF2-SHA512",
    "PBKDF2-SHA512-224",
    "PBKDF2-SHA512-256",

    # HMAC variants
    "PBKDF2-HMAC-SHA1",
    "PBKDF2-HMAC-SHA224",
    "PBKDF2-HMAC-SHA256",
    "PBKDF2-HMAC-SHA384",
    "PBKDF2-HMAC-SHA512",
    "PBKDF2-HMAC-SHA512-224",
    "PBKDF2-HMAC-SHA512-256",
}

PBKDF2_PASSWORD_HASHING_SCHEME_FAMILIES := {
    "PBKDF2",
}

PBKDF2_PASSWORD_HASHING_SCHEME_OIDS := {
    "PBKDF2": "1.2.840.113549.1.5.12",
    "PKCS5-PBKDF2": "1.2.840.113549.1.5.12",
    "PKCS5_PBKDF2_HMAC": "1.2.840.113549.1.5.12",
}

PBKDF2_PASSWORD_HASHING_SCHEME_OID_VALUES := {
    oid | oid := PBKDF2_PASSWORD_HASHING_SCHEME_OIDS[_]
}
