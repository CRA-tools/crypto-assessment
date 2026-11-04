package cbom.eccg.symmetric_constructions.symmetric_encryption_schemes.aes_modes

import data.cbom.eccg.getter_helpers.get_note
import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.classifying_helpers.is_symmetric_encryption_scheme

import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_agreed_symmetric_encryption_scheme
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_agreed_symmetric_encryption_or_authenticated_encryption_or_disk_encryption_or_key_protection_scheme
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.symmetric_encryption_scheme_metadata
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.get_iv_requirement_message
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_gcm_scheme
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.AGREED_SYMMETRIC_ENCRYPTION_SCHEME_NAMES
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_MAC_LENGTH_REQUIRED_BITS
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_PLAINTEXT_LENGTH_REQUIRED_BITS
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_INITIALIZATION_VECTOR_REQUIRED_BITS
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.GCM_INITIALIZATION_VECTOR_CONSTRUCTION

default compliant := true

compliant if count(findings) == 0

SECTION := "Symmetric-Constructions"
SUBSECTION := "Symmetric-Encryption-Schemes"

#
# Rule ECCG-SYM-ENC-001
# Flag schemes not in the agreed symmetric encryption scheme list including authenticated encryption schemes.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]
    
    is_symmetric_encryption_scheme(component)
    not is_agreed_symmetric_encryption_or_authenticated_encryption_or_disk_encryption_or_key_protection_scheme(component)

    finding := build_finding(
        "ECCG-SYM-ENC-001",
        "critical",
        sprintf(
            "Symmetric encryption scheme '%s' is not in the agreed scheme list %s.",
            [get_component_name_or_empty(component), AGREED_SYMMETRIC_ENCRYPTION_SCHEME_NAMES]
        ),
        component,
        symmetric_encryption_scheme_metadata(component),
    )
}

#
# Rule ECCG-SYM-ENC-002
# All R* schemes are only conditionally recommended.
# Without additional integrity, standalone use is considered legacy.
# TODO cover through semgrep?
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    is_agreed_symmetric_encryption_scheme(component)

    note := get_note(SECTION, SUBSECTION, "6-AddIntegrity")

    finding := build_finding(
        "ECCG-SYM-ENC-002",
        "warning",
        sprintf(
            "Scheme '%s' is only conditionally recommended; standalone use is legacy unless additional integrity is provided. The recommended integrity scheme Encrypt-then-MAC.",
            [get_component_name_or_empty(component)]
        ),
        component,
        object.union(
            symmetric_encryption_scheme_metadata(component),
            {
                "notes": note,
            }
        )
    )
}

#
# Rule ECCG-SYM-ENC-003
# IV / nonce requirement.
#
# ECCG-SYM-ENC-003 applies to the subset of agreed symmetric encryption
# schemes that require an Initialization Vector (IV) or nonce-like input.
#
# This corresponds to Note 5-IVType:
# - some schemes can use a nonce, meaning a value that is unique for a given key;
# - CBC and CFB require a random / unpredictable IV;
# - constant IVs are not accepted;
# - predictable IVs are not accepted for CBC and CFB.
#
# This rule is intentionally classification-based. It flags that the component
# is a mode where IV / nonce handling must be checked. It does not prove from
# the CBOM that the IV is unique, random, unpredictable, or correctly generated.
# TODO cover through semgrep
#
findings contains finding if {
    component := input.components[_]

    is_symmetric_encryption_scheme(component)

    note := get_note(SECTION, SUBSECTION, "5-IVType")

    finding := build_finding(
        "ECCG-SYM-ENC-003",
        "warning",
        get_iv_requirement_message(component),
        component,
        object.union(
            symmetric_encryption_scheme_metadata(component),
            {
                "notes": note,
            }
        )
    )
}

# ============================================================
# Rule ECCG-SYM-ENC-004
# GCM initialization vector (IV) requirements.
#
# In GCM mode, the IV must satisfy the agreed options defined
# in Note 23-GMAC-GCMOptions:
#
# - The IV must be exactly 96 bits long.
# - The deterministic IV construction method specified in
#   NIST SP 800-38D, Section 8.2.1, must be used.
# - Random IV construction is not an agreed option.
#
# According to Note 22-GMAC-GCMNonce, IV management must
# prevent reuse under the same key for different plaintext
# and associated-data pairs.
#
# This rule is classification-based. It flags GCM components
# whose IV generation and management must be verified.
# It does not establish whether the IV length, construction
# method, or uniqueness requirements are satisfied.
#
# TODO: Cover this through semgrep.
# ============================================================
findings contains finding if {
    component := input.components[_]

    is_symmetric_encryption_scheme(component)
    is_gcm_scheme(component)

    note := get_note(SECTION, SUBSECTION, "23-GMAC-GCMOptions")

    finding := build_finding(
        "ECCG-SYM-ENC-004",
        "warning",
        sprintf("GCM scheme detected: %s. Ensure the agreed upon %d bits of the IV and the appropriate construction %s.", [get_component_name_or_empty(component), GCM_INITIALIZATION_VECTOR_REQUIRED_BITS, GCM_INITIALIZATION_VECTOR_CONSTRUCTION]),
        component,
        object.union(
            symmetric_encryption_scheme_metadata(component),
            {
                "notes": note,
            }
        )
    )
}

# ============================================================
# Rule ECCG-SYM-ENC-005
# GCM maximum plaintext length requirement.
#
# According to Note 24-GCMPlaintextLength, the plaintext
# processed during a single GCM encryption invocation must
# not exceed 2^32 - 2 blocks of the underlying block cipher.
#
# For AES-GCM, which has a 128-bit block size, this corresponds
# to a maximum plaintext length of:
#
# (2^32 - 2) * 128 bits.
#
# Implementations must enforce this limit in environments
# where processing larger plaintexts is possible.
#
# This rule is classification-based. It flags GCM components
# for which plaintext length restrictions must be checked.
# It does not establish whether the implementation enforces
# the maximum permitted plaintext length.
#
# TODO: Cover this through semgrep.
# ============================================================
findings contains finding if {
    component := input.components[_]

    is_symmetric_encryption_scheme(component)
    is_gcm_scheme(component)

    note := get_note(SECTION, SUBSECTION, "24-GCMPlaintextLength")

    finding := build_finding(
        "ECCG-SYM-ENC-005",
        "warning",
        sprintf("GCM scheme detected: %s. Ensure the plaintext output length %s.", [get_component_name_or_empty(component), GCM_PLAINTEXT_LENGTH_REQUIRED_BITS]),
        component,
        object.union(
            symmetric_encryption_scheme_metadata(component),
            {
                "notes": note,
            }
        )
    )
}

# ============================================================
# Rule ECCG-SYM-ENC-006
# GCM authentication tag (MAC) length requirement.
#
# According to Note 25-GMAC-GCM-Bounds, the authentication
# tag must be at least 128 bits long.
#
# Note 23-GMAC-GCMOptions further restricts the agreed GCM
# options to an authentication tag length of exactly 128 bits.
#
# Consequently:
# - The authentication tag must be 128 bits (16 bytes).
# - Truncation of the authentication tag is not permitted.
# - Shorter tags, including 96-bit and 64-bit tags, are
#   not accepted under the agreed GCM options.
#
# This rule is classification-based. It flags GCM components
# whose authentication tag length must be verified.
# It does not establish whether the implementation generates
# or verifies a correctly sized authentication tag.
#
# TODO: Cover this through semgrep.
# ============================================================
findings contains finding if {
    component := input.components[_]

    is_symmetric_encryption_scheme(component)
    is_gcm_scheme(component)

    note := get_note(SECTION, SUBSECTION, "25-GMAC-GCM-Bounds")

    finding := build_finding(
        "ECCG-SYM-ENC-006",
        "warning",
        sprintf("GCM scheme detected: %s. The output length of the MAC must be %d.", [get_component_name_or_empty(component), GCM_MAC_LENGTH_REQUIRED_BITS]),
        component,
        object.union(
            symmetric_encryption_scheme_metadata(component),
            {
                "notes": note,
            }
        )
    )
}
