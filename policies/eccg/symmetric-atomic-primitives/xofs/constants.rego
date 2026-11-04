package cbom.eccg.symmetric_atomic_primitives.xofs.constants 

import data.cbom.eccg.oid_constants.NO_OID

MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF := 256

# ============================================================
# SHAKE (FIPS 202)
# ============================================================
#
# Sources:
# - NIST FIPS 202:
#   https://doi.org/10.6028/NIST.FIPS.202
# - NIST CSOR (OIDs):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
#
SHAKE_XOF_ALGORITHM_NAMES := {
    "SHAKE128",
    "SHAKE256",
}

SHAKE_XOF_ALGORITHM_FAMILIES := {
    "SHA-3",
}

SHAKE_XOF_ALGORITHM_OIDS := {
    "SHAKE128": "2.16.840.1.101.3.4.2.11",
    "SHAKE256": "2.16.840.1.101.3.4.2.12",
}

SHAKE_XOF_ALGORITHM_OID_VALUES := {oid | oid := SHAKE_XOF_ALGORITHM_OIDS[_]}


# ============================================================
# cSHAKE (NIST SP 800-185)
# ============================================================
#
# Source:
# - NIST SP 800-185:
#   https://doi.org/10.6028/NIST.SP.800-185
#
# No general-purpose cSHAKE OIDs verified in NIST CSOR.
#
CSHAKE_XOF_ALGORITHM_NAMES := {
    "CSHAKE128",
    "CSHAKE256",
}

CSHAKE_XOF_ALGORITHM_FAMILIES := {
    "SHA-3",
}

CSHAKE_XOF_ALGORITHM_OIDS := {
    "CSHAKE128": NO_OID,
    "CSHAKE256": NO_OID,
}

CSHAKE_XOF_ALGORITHM_OID_VALUES := {oid | oid := CSHAKE_XOF_ALGORITHM_OIDS[_]}

