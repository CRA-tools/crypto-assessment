package cbom.eccg.symmetric_constructions.key_derivation

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.getter_helpers.get_note
import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.classifying_helpers.is_kdf_primitive

import data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_kdf_scheme_metadata
import data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_agreed_kdf_scheme
import data.cbom.eccg.symmetric_constructions.key_derivation.helpers.is_pbkdf2_scheme

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Key-Derivation-Functions"

# ECCG Section 3.7 explicitly describes this list as non-exhaustive.
# An unlisted KDF requires review rather than a confirmed rejection.
findings contains finding if {
    some i
    component := input.components[i]

    is_kdf_primitive(component)
    not is_agreed_kdf_scheme(component)

    finding := build_finding(
        "ECCG-KDF-001",
        "medium",
        sprintf(
            "KDF scheme '%s' is not identified among the listed ECCG constructions: HKDF, PBKDF2, ANSI-X9.63-KDF, and NIST SP800-56A/B/C. This list is not exhaustive; review the construction and its parameters before determining compliance.",
            [get_component_name_or_empty(component)]
        ),
        component,
        is_kdf_scheme_metadata(component)
    )
}

# Note 26 requires an agreed PRF. Key lengths are not established by the
# construction name, so the HMAC pre-hashing condition remains an advisory.
findings contains finding if {
    some i
    component := input.components[i]

    is_kdf_primitive(component)
    is_pbkdf2_scheme(component)

    note := get_note(SECTION, SUBSECTION, "26-PBKDF2-PRF")

    finding := build_finding(
        "ECCG-KDF-002",
        "warning",
        sprintf(
            "PBKDF2 scheme detected: %s. Ensure that the underlying pseudo-random function (PRF) is an agreed cryptographic mechanism. If HMAC is used, verify that the HMAC key length does not exceed the underlying hash function's message block length without considering the security implications. Longer keys are pre-hashed, which may reduce the effective entropy of the key derived using PBKDF2. Note that this might overlap with password-hashing, since they mostly use the same underlying primitives.",
            [get_component_name_or_empty(component)]
        ),
        component,
        object.union(
            is_kdf_scheme_metadata(component),
            {
                "notes": note
            }
        )
    )
}
