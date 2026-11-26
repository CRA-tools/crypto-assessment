package cbom.eccg.symmetric_constructions.macs.constants

import data.cbom.eccg.oid_constants.NO_OID

MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_MACS := 192
MINIMUM_MAC_BITS_TRUNCATED_OUTPUT := 96
GMAC_INITIALIZATION_VECTOR_REQUIRED_BITS := 96
GMAC_INITIALIZATION_VECTOR_CONSTRUCTION := "NIST SP 800-38D, Section 8.2.1."

#
# Sources:
# - NIST SP 800-38B:
#   https://doi.org/10.6028/NIST.SP.800-38B
# - ISO/IEC 9797-1:2011, Annex A (MAC Algorithm 5):
#   https://www.iso.org/standard/50375.html
#
# The ISO OID identifies MAC Algorithm 5 (CMAC/OMAC1).
# It does not independently identify the underlying
# block cipher or its key size.
#
CMAC_MAC_ALGORITHM_NAMES := {
    "CMAC",
    "AES-128-CMAC",
    "AES-192-CMAC",
    "AES-256-CMAC",
}

CMAC_MAC_ALGORITHM_FAMILIES := {
    "CMAC",
}

CMAC_MAC_ALGORITHM_OIDS := {
    "CMAC": "1.0.9797.1.3.5",
}

CMAC_MAC_ALGORITHM_OID_VALUES = {oid | oid := CMAC_MAC_ALGORITHM_OIDS[_]}

#
# Source:
# - ISO/IEC 9797-1:2011, Annex A (MAC Algorithm 1):
#   https://www.iso.org/standard/50375.html
#
# OID identifies MAC Algorithm 1, not Padding Method 2.
# Padding must be validated separately.
#
# CBC-MAC is not a separate CycloneDX registry family.
#
CBC_MAC_ALGORITHM_NAMES := {
    "CBC-MAC",
}

CBC_MAC_ALGORITHM_FAMILIES := {
    "CBC-MAC": NO_OID,
}

CBC_MAC_ALGORITHM_OIDS := {
    "CBC-MAC": "1.0.9797.1.3.1",
}

CBC_MAC_ALGORITHM_OID_VALUES = {oid | oid := CBC_MAC_ALGORITHM_OIDS[_]}


# HMAC
# Sources:
# - RFC 4231, Section 3.1:
#   https://www.rfc-editor.org/rfc/rfc4231.html
# - RFC 8018, Appendix B.1:
#   https://www.rfc-editor.org/rfc/rfc8018.html
# - NIST CSOR (HMAC-SHA3):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
#
# Generic HMAC has no single OID.
# OIDs identify HMAC with specific hash functions.
#
# HMAC SHA-1
# Source:
# - RFC 8018, Appendix B.1:
#   https://www.rfc-editor.org/rfc/rfc8018.html
#
# ECCG: Acceptable (A), until 2030.
#

HMAC_SHA1_LEGACY_MARKER := "L[2030]"

HMAC_SHA1_ALGORITHM_NAMES := {
    "HMAC-SHA-1",
}

HMAC_SHA1_ALGORITHM_OIDS := {
    "HMAC-SHA-1": "1.2.840.113549.2.7",
}

HMAC_SHA1_ALGORITHM_OID_VALUES := {
    oid | oid := HMAC_SHA1_ALGORITHM_OIDS[_]
}

HMAC_MAC_ALGORITHM_FAMILIES := {
    "HMAC",
}


HMAC_MAC_ALGORITHM_NAMES := {
    "HMAC",
}

HMAC_MAC_ALGORITHM_OIDS := {
    "HMAC-SHA-224":     "1.2.840.113549.2.8",
    "HMAC-SHA-256":     "1.2.840.113549.2.9",
    "HMAC-SHA-384":     "1.2.840.113549.2.10",
    "HMAC-SHA-512":     "1.2.840.113549.2.11",
    "HMAC-SHA-512/224": "1.2.840.113549.2.12",
    "HMAC-SHA-512/256": "1.2.840.113549.2.13",

    "HMAC-SHA3-224": "2.16.840.1.101.3.4.2.13",
    "HMAC-SHA3-256": "2.16.840.1.101.3.4.2.14",
    "HMAC-SHA3-384": "2.16.840.1.101.3.4.2.15",
    "HMAC-SHA3-512": "2.16.840.1.101.3.4.2.16",
}


HMAC_MAC_ALGORITHM_OID_VALUES := {
    oid | oid := HMAC_MAC_ALGORITHM_OIDS[_]
}

#
# Sources:
# - NIST SP 800-185:
#   https://doi.org/10.6028/NIST.SP.800-185
# - RFC 8702, Section 2:
#   https://www.rfc-editor.org/rfc/rfc8702.html#section-2
#
KMAC_MAC_ALGORITHM_NAMES := {
    "KMAC128",
    "KMAC256",
}

KMAC_MAC_ALGORITHM_FAMILIES := {
    "SHA-3",
}

KMAC_MAC_ALGORITHM_OIDS := {
    "KMAC128": "2.16.840.1.101.3.4.2.19",
    "KMAC256": "2.16.840.1.101.3.4.2.20",
}

KMAC_MAC_ALGORITHM_OID_VALUES = {oid | oid := KMAC_MAC_ALGORITHM_OIDS[_]}


#
# Sources:
# - NIST SP 800-38D:
#   https://doi.org/10.6028/NIST.SP.800-38D
# - RFC 9044, Section 3.1:
#   https://www.rfc-editor.org/rfc/rfc9044.html#section-3.1
#
GMAC_MAC_ALGORITHM_NAMES := {
    "GMAC",
    "AES-128-GMAC",
    "AES-192-GMAC",
    "AES-256-GMAC",
}

GMAC_MAC_ALGORITHM_FAMILIES := {
    "AES",
}

GMAC_MAC_ALGORITHM_OIDS := {
    "AES-128-GMAC": "2.16.840.1.101.3.4.1.9",
    "AES-192-GMAC": "2.16.840.1.101.3.4.1.29",
    "AES-256-GMAC": "2.16.840.1.101.3.4.1.49",
}

GMAC_MAC_ALGORITHM_OID_VALUES = {oid | oid := GMAC_MAC_ALGORITHM_OIDS[_]}


