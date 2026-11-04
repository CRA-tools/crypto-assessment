package cbom.eccg.symmetric_atomic_primitives.hashes.constants 

MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_HASH := 384

#
# Sources:
# - NIST Computer Security Objects Register (CSOR):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
# - RFC 8017, Appendix B.1:
#   https://www.rfc-editor.org/rfc/rfc8017.html#appendix-B.1
#
# Base OID: 2.16.840.1.101.3.4.2
#

SHA2_HASH_ALGORITHM_NAMES := {
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-512/256",
}

SHA2_HASH_ALGORITHM_FAMILIES := {
    "SHA-2",
}

SHA2_HASH_ALGORITHM_OIDS := {
    "SHA-256": "2.16.840.1.101.3.4.2.1",  # SHA-256
    "SHA-384": "2.16.840.1.101.3.4.2.2",  # SHA-384
    "SHA-512": "2.16.840.1.101.3.4.2.3",  # SHA-512
    "SHA-512/256": "2.16.840.1.101.3.4.2.6",  # SHA-512/256
}

SHA2_HASH_ALGORITHM_OID_VALUES := {oid | oid := SHA2_HASH_ALGORITHM_OIDS[_]}

#
# Source:
# - NIST Computer Security Objects Register (CSOR):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
#
# Base OID: 2.16.840.1.101.3.4.2
#
SHA3_HASH_ALGORITHM_NAMES := {
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
}

SHA3_HASH_ALGORITHM_FAMILIES := {
    "SHA-3",
}

SHA3_HASH_ALGORITHM_OIDS := {
    "SHA3-256": "2.16.840.1.101.3.4.2.8",   # SHA3-256
    "SHA3-384": "2.16.840.1.101.3.4.2.9",   # SHA3-384
    "SHA3-512": "2.16.840.1.101.3.4.2.10",  # SHA3-512
}

SHA3_HASH_ALGORITHM_OID_VALUES := {oid | oid := SHA3_HASH_ALGORITHM_OIDS[_]}


