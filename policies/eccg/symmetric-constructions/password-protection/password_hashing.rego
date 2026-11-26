package cbom.eccg.symmetric_constructions.password_hashing

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.getter_helpers.get_note
import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.classifying_helpers.is_password_hashing_primitive

import data.cbom.eccg.symmetric_constructions.password_protection.helpers.is_agreed_password_protection_scheme
import data.cbom.eccg.symmetric_constructions.password_protection.helpers.is_pbkdf2_scheme
import data.cbom.eccg.symmetric_constructions.password_protection.helpers.is_argon2id_scheme
import data.cbom.eccg.symmetric_constructions.password_protection.helpers.AGREED_PASSWORD_HASHING_SCHEMES
import data.cbom.eccg.symmetric_constructions.password_protection.helpers.password_protection_scheme_metadata
import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_ITERATIONS_REQUIRED
import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_PARALLELISM_REQUIRED
import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_MEMORY_REQUIRED_KIB
import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_TAG_REQUIRED_BITS
import data.cbom.eccg.symmetric_constructions.password_protection.constants.ARGON2ID_SALT_REQUIRED_BITS

default compliant := true
compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Password-Protection"

#
# --------------------------------------------------
# Rule ECCG-PWH-001
# PBKDF2 and Argon2 are the only agreed algorithms for password hashing.
# --------------------------------------------------
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_password_hashing_primitive(component)
    not is_agreed_password_protection_scheme(component)

    finding := build_finding(
        "ECCG-PWH-001",
        "medium",
        sprintf(
            "Password hashing mechanism '%s' is not based on the agreed schemes. Note that there is no way to differentiate, whether this is a KDF or a password hash from the CBOM alone. The agreed schemes are: %s",
            [get_component_name_or_empty(component), AGREED_PASSWORD_HASHING_SCHEMES]
        ),
        component,
        password_protection_scheme_metadata(component),
    )
}

# ============================================================
# Rule ECCG-PWH-002
# PBKDF2 iteration count and salt requirements.
#
# ECCG classification: Warning
#
# According to Note 28-NumberOfIterations:
# - The PBKDF2 iteration count should be as large as
#   practically possible without impeding legitimate use.
# - A sufficiently high iteration count increases the
#   computational cost of brute-force attacks.
#
# According to Note 29-Salt:
# - A cryptographically random salt must be generated
#   when the password is registered.
# - The salt must be at least 128 bits long.
# - The salt must be stored alongside the password
#   verification value.
#
# Detection:
# - Identifies PBKDF2 password hashing components.
# - Emits a warning describing the required parameters.
#
# This rule is classification-based. It does not verify
# the actual iteration count, salt length, or randomness.
#
findings contains finding if {
    component := input.components[_]

    is_password_hashing_primitive(component)
    is_pbkdf2_scheme(component)

    note_ids := [
        "28-NumberOfIterations",
        "29-Salt"
    ]
    
    notes := [
        get_note(SECTION, SUBSECTION, note_id) |
        note_id := note_ids[_]
    ]

    finding := build_finding(
        "ECCG-PWH-002",
        "warning",
        sprintf(
            "PBKDF2 password hashing scheme detected: %s. Ensure that the iteration count is set as high as practically possible without impeding legitimate use, to increase resistance against brute-force attacks. Additionally, a cryptographically random salt of at least 128 bits must be generated when the password is registered and stored alongside the password verification value to prevent precomputation attacks.",
            [get_component_name_or_empty(component)]
        ),
        component,
        object.union(
            password_protection_scheme_metadata(component),
            {
                "notes": notes,
            }
        )
    )
}


# ============================================================
# Rule ECCG-PWH-003
# Argon2id password hashing parameter requirements.
#
# ECCG classification: Warning
#
# According to Note 27-Argon Parameters, the agreed
# Argon2id configuration requires:
#
# - Iteration count (t): 1
# - Parallelism (p): 4 lanes
# - Memory cost (m): 2^21 KiB (2 GiB)
# - Salt length: 128 bits
# - Tag length: 256 bits
#
# Detection:
# - Identifies Argon2id password hashing components.
# - Emits a warning describing the agreed parameter set.
#
# This rule is classification-based. It does not verify
# whether the actual Argon2id parameters comply.
#

findings contains finding if {
    component := input.components[_]

    is_password_hashing_primitive(component)
    is_argon2id_scheme(component)

    note := get_note(SECTION, SUBSECTION, "27-Argon Parameters")

    finding := build_finding(
        "ECCG-PWH-003",
        "warning",
        sprintf(
            "Argon2id password hashing scheme detected: %s. Ensure that the agreed ECCG parameters are used: %d iteration, %d parallel lanes, %d KiB (2 GiB) of memory, a %d-bit salt, and a %d-bit authentication tag.",
            [
                get_component_name_or_empty(component),
                ARGON2ID_ITERATIONS_REQUIRED,
                ARGON2ID_PARALLELISM_REQUIRED,
                ARGON2ID_MEMORY_REQUIRED_KIB,
                ARGON2ID_SALT_REQUIRED_BITS,
                ARGON2ID_TAG_REQUIRED_BITS
            ]
        ),
        component,
        object.union(
            password_protection_scheme_metadata(component),
            {
                "notes": note
            }
        )
    )
}
