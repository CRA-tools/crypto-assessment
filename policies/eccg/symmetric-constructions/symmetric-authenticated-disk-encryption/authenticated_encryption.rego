package cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.authenticated_encryption

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.classifying_helpers.is_ae_primitive

import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_agreed_authenticated_encryption_scheme
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.symmetric_encryption_scheme_metadata
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants.SEAS_CHALLENGE_SIZE_REQUIRED_BITS



default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Symmetric-Authenticated-Encryption"


# ============================================================
# Rule ECCG-SEAS-001
# Non-agreed authenticated encryption scheme.
#
# Authenticated encryption schemes must belong to the set
# of cryptographic constructions agreed upon by the ECCG.
#
# This rule identifies components classified as authenticated
# encryption (AE) primitives that are not recognized as
# agreed authenticated encryption schemes.
#
# This rule is classification-based. It flags AE components
# that do not match the recognized agreed schemes.
#
# ============================================================
findings contains finding if {
    some i
    component := input.components[i]

    is_ae_primitive(component)
    not is_agreed_authenticated_encryption_scheme(component)


    finding := build_finding(
        "ECCG-SEAS-001",
        "critical",
        sprintf("%s is not an agreed Authenticated Encryption scheme.", [get_component_name_or_empty(component)]),
        component,
        symmetric_encryption_scheme_metadata(component)
    )
}

# ============================================================
# Rule ECCG-SEAS-002
# Authenticated encryption challenge requirements.
#
# Agreed authenticated encryption schemes must satisfy
# the challenge requirements defined by the ECCG.
#
# - Challenges must not be reused under the same key.
# - The challenge size must satisfy the required number
#   of bits specified by SEAS_CHALLENGE_SIZE_REQUIRED_BITS.
#
# Challenge reuse may compromise the security guarantees
# of authenticated encryption, depending on the scheme.
#
# This rule is classification-based. It identifies agreed
# authenticated encryption components whose challenge
# generation and management must be verified.
#
# It does not establish whether challenges are unique,
# correctly generated, or of the required bit length.
#
# ============================================================
findings contains finding if {
    some i
    component := input.components[i]

    is_ae_primitive(component)
    is_agreed_authenticated_encryption_scheme(component)


    finding := build_finding(
        "ECCG-SEAS-002",
        "warning",
        sprintf("%s detected. When using Authenticated Encryption schemes ensure that the challenges are not reused and the challenge bits are %d.", [get_component_name_or_empty(component), SEAS_CHALLENGE_SIZE_REQUIRED_BITS]),
        component,
        symmetric_encryption_scheme_metadata(component)
    )
}

