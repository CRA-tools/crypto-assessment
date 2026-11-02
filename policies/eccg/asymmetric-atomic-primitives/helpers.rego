package cbom.eccg.asymmetric_atomic_primitives.helpers

import data.cbom.eccg.helpers.is_public_key_primitive
import data.cbom.eccg.helpers.is_asymmetric_algorithm
import data.cbom.eccg.helpers.get_name_or_unknown
import data.cbom.eccg.helpers.normalize_crypto_name
import data.cbom.eccg.helpers.normalize_ec_curve_name
import data.cbom.eccg.helpers.get_ec_curve_or_unknown
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.legacy_marker_status
import data.cbom.eccg.helpers.legacy_status_message
import data.cbom.eccg.helpers.legacy_status_severity

#
# ---------------------------------------------------------
# Helper: eccg_recommended_ec_curve_names
#
# Purpose:
# Set of normalized curve identifiers accepted by ECCG for the
# EC-DLOG parameter table.
#
# Includes:
# - Direct CycloneDX registry names
# - Common aliases for the same recommended curves
#
# NIST aliases:
# - nist/P-256       == secg/secp256r1 == x962/prime256v1 == prime256v1
# - nist/P-384       == secg/secp384r1
# - nist/P-521       == secg/secp521r1
#
# Brainpool aliases:
# - brainpool/brainpoolP256r1
# - brainpool/brainpoolP384r1
# - brainpool/brainpoolP512r1
#
# FR aliases:
# - anssi/FRP256v1
# - FRP256v1
#
# Edwards family [RFC7748]
#
# CycloneDX registry names:
# - other/Curve25519
# - other/Curve448
# ---------------------------------------------------------
#
eccg_recommended_ec_curve_names contains "brainpoolbrainpoolp256r1"
eccg_recommended_ec_curve_names contains "brainpoolp256r1"

eccg_recommended_ec_curve_names contains "brainpoolbrainpoolp384r1"
eccg_recommended_ec_curve_names contains "brainpoolp384r1"

eccg_recommended_ec_curve_names contains "brainpoolbrainpoolp512r1"
eccg_recommended_ec_curve_names contains "brainpoolp512r1"

eccg_recommended_ec_curve_names contains "nistp256"
eccg_recommended_ec_curve_names contains "p256"
eccg_recommended_ec_curve_names contains "secgsecp256r1"
eccg_recommended_ec_curve_names contains "secp256r1"
eccg_recommended_ec_curve_names contains "x962prime256v1"
eccg_recommended_ec_curve_names contains "prime256v1"

eccg_recommended_ec_curve_names contains "nistp384"
eccg_recommended_ec_curve_names contains "p384"
eccg_recommended_ec_curve_names contains "secgsecp384r1"
eccg_recommended_ec_curve_names contains "secp384r1"

eccg_recommended_ec_curve_names contains "nistp521"
eccg_recommended_ec_curve_names contains "p521"
eccg_recommended_ec_curve_names contains "secgsecp521r1"
eccg_recommended_ec_curve_names contains "secp521r1"

eccg_recommended_ec_curve_names contains "anssifrp256v1"
eccg_recommended_ec_curve_names contains "frp256v1"

eccg_recommended_ec_curve_names contains "othercurve25519"
eccg_recommended_ec_curve_names contains "curve25519"

eccg_recommended_ec_curve_names contains "othercurve448"
eccg_recommended_ec_curve_names contains "curve448"


# Edwards-based digital signatures [RFC8032]
#
# CycloneDX registry names:
# - other/Ed25519
# - other/Ed448
#
# IMPORTANT:
# Ed25519 and Ed448 are digital signature algorithms, not curve names.
# They use Edwards25519 and Edwards448, respectively, which are
# mathematically related to Curve25519 and Curve448.
#
# These identifiers are included for compatibility with CycloneDX,

eccg_recommended_ec_curve_names contains "othered25519"
eccg_recommended_ec_curve_names contains "ed25519"

eccg_recommended_ec_curve_names contains "othered448"
eccg_recommended_ec_curve_names contains "ed448"

is_rsa_primitive(component) if {
    is_public_key_primitive(component)
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)
    contains(normalized_name, "rsa")
} else if {
    component.cryptoProperties.assetType == "algorithm"

    props := component.cryptoProperties.algorithmProperties
    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_name(family)

    contains(normalized_family, "rsa")
} else if {
    component.cryptoProperties.assetType == "algorithm"

    props := component.cryptoProperties.algorithmProperties
    primitive := lower(object.get(props, "primitive", ""))
    primitive == "signature"

    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)
    contains(normalized_name, "rsa")
} else if {
    is_asymmetric_algorithm(component)
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)
    contains(normalized_name, "rsa")
}



RSA_SECTION := "Asymmetric-Atomic-Primitives"
RSA_SUBSECTION := "RSA-Integer-Factorization"
RSA_LEGACY_MARKER := "L[2025]"

rsa_legacy_modulus_size(n) if {
    n >= 1900
    n < 3000
}

rsa_recommended_modulus_size(n) if {
    n >= 3000
}

classify_rsa_modulus(n) = "recommended" if {
    rsa_recommended_modulus_size(n)
} else = "legacy" if {
    rsa_legacy_modulus_size(n)
} else = "not_agreed" if {
    true
}

rsa_modulus_status(n) := status if {
    rsa_legacy_modulus_size(n)
    status := legacy_marker_status(RSA_LEGACY_MARKER)
} else := "not_agreed"

rsa_modulus_severity(n) := severity if {
    rsa_legacy_modulus_size(n)
    status := legacy_marker_status(RSA_LEGACY_MARKER)
    severity := legacy_status_severity(status)
} else := "critical"

rsa_modulus_message(n, status) := message if {
    rsa_legacy_modulus_size(n)
    legacy_message := legacy_status_message("RSA modulus size", RSA_LEGACY_MARKER, status)
    message := sprintf(
        "RSA modulus size must be >=3000 bits and must satisfy log2(e) > 16. Detected n=%d bits. The public exponent condition could not be verified from CycloneDX data. %s",
        [n, legacy_message],
    )
} else := message if {
    message := sprintf(
        "RSA modulus size must be >=3000 bits and must satisfy log2(e) > 16. Detected non-agreed modulus size n=%d bits. The public exponent condition could not be verified from CycloneDX data.",
        [n],
    )
}

rsa_modulus_notes(n) := note if {
    rsa_legacy_modulus_size(n)
    note := get_note(RSA_SECTION, RSA_SUBSECTION, "30-LegacyRSA")
} else := {} if {
    true
}

#
# ---------------------------------------------------------
# Helper: is_ffdlog_primitive
#
# Purpose:
# Detect finite-field discrete logarithm (FF-DLOG) primitives
# and closely related finite-field Diffie-Hellman groups.
#
# ECCG context:
# - FF-DLOG refers to the finite-field discrete logarithm
#   hardness assumption.
# - MODP groups [RFC3526] and FFDHE groups [RFC7919] are
#   finite-field groups used by Diffie-Hellman-style schemes.
#
# Key clarification:
# - FFDHE (Finite Field Diffie-Hellman Ephemeral) operates in
#   the multiplicative group of a finite field:
#       X = g^x mod p
# - Therefore:
#       FFDHE ⇒ FF-DLOG primitive
#
# Detection strategy:
# - Prefer explicit FF-DLOG indicators when present.
# - Detect standardized group names such as:
#     • FFDH / FFDHE (CycloneDX pattern: FFDH(E)-{parameterSetIdentifier})
#     • FFDHE (including TLS named groups like ffdhe2048)
#     • MODP
# - Fall back to finite-field Diffie-Hellman naming:
#     • DH
#
# Rationale:
# CycloneDX / CBOM tools may not emit "FF-DLOG" directly.
# In practice, finite-field DH components represent usage of
# the FF-DLOG primitive/assumption.
#
# Notes:
# - This helper explicitly treats FFDH/FFDHE as FF-DLOG.
# - This helper must NOT match elliptic-curve Diffie-Hellman:
#     • ECDH, ECDHE
#     • X25519, X448
# - Name matching is normalized to tolerate formatting differences.
# ---------------------------------------------------------
#
is_ffdlog_primitive(component) if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    # Explicit FF-DLOG naming
    contains(normalized_name, "ffdlog")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    # CycloneDX FFDH family / FFDHE groups (e.g., FFDH-ffdhe3072)
    # → Direct mapping to FF-DLOG
    contains(normalized_name, "ffdh")
} else if {
    props := component.cryptoProperties.algorithmProperties

    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_name(family)

    # CycloneDX cryptography registry family.
    normalized_family == "ffdh"
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    # FFDHE groups (e.g., ffdhe2048, ffdhe3072)
    # → Direct mapping to FF-DLOG
    contains(normalized_name, "ffdhe")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    # MODP groups (RFC3526)
    contains(normalized_name, "modp")
} else if {
    props := component.cryptoProperties.algorithmProperties

    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_name(family)

    contains(normalized_family, "ffdlog")
} else if {
    props := component.cryptoProperties.algorithmProperties

    primitive := object.get(props, "primitive", "")
    normalized_primitive := normalize_crypto_name(primitive)

    contains(normalized_primitive, "ffdlog")
} else if {
    #
    # Fallback: finite-field Diffie-Hellman.
    #
    # Only match DH after excluding elliptic-curve variants.
    #
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    not contains(normalized_name, "ecdh")
    not contains(normalized_name, "ecdhe")
    not contains(normalized_name, "x25519")
    not contains(normalized_name, "x448")

    contains(normalized_name, "dh")
} else if {
    #
    # Fallback: finite-field Diffie-Hellman.
    #
    # Only match DH after excluding elliptic-curve variants.
    #
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    not contains(normalized_name, "ecdh")
    not contains(normalized_name, "ecdhe")
    not contains(normalized_name, "x25519")
    not contains(normalized_name, "x448")

    contains(normalized_name, "dhe")
}

#
# ---------------------------------------------------------
# Helper: get_ffdlog_group_family_or_unknown
#
# Purpose:
# Identify whether an FF-DLOG component is one of the ECCG
# agreed standardized finite-field parameter families.
#
# ECCG agrees:
# - MODP groups from RFC3526
# - FFDHE groups from RFC7919
#
# Detection order:
# - component.name
# - algorithmProperties.algorithmFamily
# - algorithmProperties.parameterSetIdentifier, for registry-style values
#   that include the family name, such as "ffdhe3072".
# ---------------------------------------------------------
#
get_ffdlog_group_family_or_unknown(component) := "MODP" if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)
    contains(normalized_name, "modp")
} else := "FFDHE" if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)
    contains(normalized_name, "ffdhe")
} else := "MODP" if {
    props := component.cryptoProperties.algorithmProperties
    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_name(family)
    contains(normalized_family, "modp")
} else := "FFDHE" if {
    props := component.cryptoProperties.algorithmProperties
    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_name(family)
    contains(normalized_family, "ffdhe")
} else := "FFDHE" if {
    props := component.cryptoProperties.algorithmProperties
    family := object.get(props, "algorithmFamily", "")
    normalized_family := normalize_crypto_name(family)
    normalized_family == "ffdh"

    parameter_set := object.get(props, "parameterSetIdentifier", "")
    normalized_parameter_set := normalize_crypto_name(parameter_set)
    contains(normalized_parameter_set, "ffdhe")
} else := "MODP" if {
    props := component.cryptoProperties.algorithmProperties
    parameter_set := object.get(props, "parameterSetIdentifier", "")
    normalized_parameter_set := normalize_crypto_name(parameter_set)
    contains(normalized_parameter_set, "modp")
} else := "FFDHE" if {
    props := component.cryptoProperties.algorithmProperties
    parameter_set := object.get(props, "parameterSetIdentifier", "")
    normalized_parameter_set := normalize_crypto_name(parameter_set)
    contains(normalized_parameter_set, "ffdhe")
} else := "unknown"

is_eccg_agreed_ffdlog_group_family(component) if {
    family := get_ffdlog_group_family_or_unknown(component)
    family == "MODP"
} else if {
    family := get_ffdlog_group_family_or_unknown(component)
    family == "FFDHE"
}

#
# ---------------------------------------------------------
# Helper: get_ffdlog_group_bits_or_unknown
#
# Purpose:
# Extract the FF-DLOG group size in bits.
#
# Preferred source:
# - numeric algorithmProperties.parameterSetIdentifier
#
# Fallback:
# - known standardized group-size tokens in component.name or
#   algorithmProperties.parameterSetIdentifier, such as "ffdhe3072"
#   or "modp2048".
# ---------------------------------------------------------
#
get_ffdlog_group_bits_or_unknown(component) := bits if {
    bits := get_parameter_set_identifier_to_number_or_unknown(component)
    bits != "unknown"
} else := 2048 if {
    ffdlog_group_size_token_present(component, "2048")
} else := 3072 if {
    ffdlog_group_size_token_present(component, "3072")
} else := 4096 if {
    ffdlog_group_size_token_present(component, "4096")
} else := 6144 if {
    ffdlog_group_size_token_present(component, "6144")
} else := 8192 if {
    ffdlog_group_size_token_present(component, "8192")
} else := "unknown"

ffdlog_group_size_token_present(component, token) if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)
    contains(normalized_name, token)
} else if {
    props := component.cryptoProperties.algorithmProperties
    parameter_set := object.get(props, "parameterSetIdentifier", "")
    normalized_parameter_set := normalize_crypto_name(parameter_set)
    contains(normalized_parameter_set, token)
}

FFDLOG_SECTION := "Asymmetric-Atomic-Primitives"
FFDLOG_SUBSECTION := "FF-DLOG"
FFDLOG_LEGACY_MARKER := "L[2025]"

ff_dlog_legacy_size(p_bits) if {
    p_bits > 1900
    p_bits < 3000
}

ff_dlog_size_status(p_bits) := status if {
    ff_dlog_legacy_size(p_bits)
    status := legacy_marker_status(FFDLOG_LEGACY_MARKER)
} else := "not_agreed"

ff_dlog_size_severity(p_bits) := severity if {
    ff_dlog_legacy_size(p_bits)
    status := legacy_marker_status(FFDLOG_LEGACY_MARKER)
    severity := legacy_status_severity(status)
} else := "critical"

ff_dlog_size_message(p_bits, status) := message if {
    ff_dlog_legacy_size(p_bits)
    legacy_message := legacy_status_message("FF-DLOG group size", FFDLOG_LEGACY_MARKER, status)
    message := sprintf(
        "MODP and FFDHE group size must be >=3072 bits. Detected p=%d bits. %s",
        [p_bits, legacy_message],
    )
} else := message if {
    message := sprintf(
        "MODP and FFDHE group size must be >=3072 bits. Detected non-agreed group size p=%d bits.",
        [p_bits],
    )
}

ff_dlog_size_notes(p_bits) := notes if {
    ff_dlog_legacy_size(p_bits)

    precomputation_note := get_note(FFDLOG_SECTION, FFDLOG_SUBSECTION, "33-Precomputation")
    legacy_note := get_note(FFDLOG_SECTION, FFDLOG_SUBSECTION, "34-LegacyFF-DLOG")

    notes := {
        "precomputation": precomputation_note,
        "legacy": legacy_note,
    }
} else := {}

#
# ---------------------------------------------------------
# Helper: is_ecdlog_primitive
#
# Purpose:
# Detect elliptic-curve discrete logarithm (EC-DLOG) primitives
# and elliptic-curve constructions that rely on EC-DLOG.
#
# ECCG context:
# - EC-DLOG refers to the discrete logarithm problem in the group
#   of rational points of an elliptic curve over a finite field.
# - ECCG agrees only elliptic curves over prime fields.
#
# Detection strategy:
# - Prefer explicit EC-DLOG indicators in the component name or
#   algorithmProperties.primitive.
# - Treat algorithm components with extractable EC curve metadata as
#   EC-DLOG-bearing primitives, even if the component name is generic.
# - Detect EC key-agreement algorithms:
#     • ECDH
#     • ECDHE
#     • X25519
#     • X448
# - Detect EC signature algorithms:
#     • ECDSA
#     • Ed25519
#     • Ed448
#     • EdDSA
# - Detect EC encryption schemes:
#     • ECIES
#     • EC-ElGamal
#
# Notes:
# - X3DH is a protocol built on EC key agreement, not itself an
#   atomic primitive. It should normally be handled at protocol level.
# - This helper detects EC-DLOG usage; curve compliance is checked
#   separately by is_eccg_recommended_ec_curve().
# ---------------------------------------------------------
#
is_ecdlog_primitive(component) if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecdlog")
} else if {
    component.cryptoProperties.assetType == "algorithm"

    props := object.get(component.cryptoProperties, "algorithmProperties", {})
    primitive := object.get(props, "primitive", "")
    normalized_primitive := normalize_crypto_name(primitive)

    contains(normalized_primitive, "ecdlog")
} else if {
    component.cryptoProperties.assetType == "algorithm"

    curve := get_ec_curve_or_unknown(component)
    curve != "unknown"
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecdh")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecdhe")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "x25519")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "x448")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecdsa")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "eddsa")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ed25519")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ed448")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecies")
} else if {
    name := get_name_or_unknown(component)
    normalized_name := normalize_crypto_name(name)

    contains(normalized_name, "ecelgamal")
}

#
# ---------------------------------------------------------
# Helper: is_eccg_recommended_ec_curve
#
# Purpose:
# Match elliptic curves against the ECCG recommended EC-DLOG
# parameter table.
#
# ECCG recommended curves:
#
# Brainpool [RFC5639]
# - BrainpoolP256r1
# - BrainpoolP384r1
# - BrainpoolP512r1
#
# NIST [FIPS 186-4, Appendix D.1.2]
# - NIST P-256
# - NIST P-384
# - NIST P-521
#
# FR [JORF]
# - FRP256v1
#
# Important:
# - ECCG recommends the above named curves.
# - Other curves in the CycloneDX registry, such as BLS, BN,
#   secp256k1, binary NIST B/K curves, GOST, SM2, NUMS, and
#   miscellaneous curves, are not matched here.
# ---------------------------------------------------------
#
is_eccg_recommended_ec_curve(curve) if {
    normalized := normalize_ec_curve_name(curve)
    normalized in eccg_recommended_ec_curve_names
}


#
# ---------------------------------------------------------
# Helper: get_eccg_ec_curve_family_or_unknown
#
# Purpose:
# Return the ECCG curve family for a recommended curve.
#
# Families from ECCG:
# - Brainpool [RFC5639]
# - NIST [FIPS186-4, Appendix D.1.2]
# - FR [JORF]
# ---------------------------------------------------------
#
get_eccg_ec_curve_family_or_unknown(curve) := "Brainpool [RFC5639]" if {
    normalized := normalize_ec_curve_name(curve)
    startswith(normalized, "brainpool")
} else := "NIST [FIPS186-4, Appendix D.1.2]" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "nistp256",
        "p256",
        "secgsecp256r1",
        "secp256r1",
        "x962prime256v1",
        "prime256v1",
        "nistp384",
        "p384",
        "secgsecp384r1",
        "secp384r1",
        "nistp521",
        "p521",
        "secgsecp521r1",
        "secp521r1"
    }

    normalized == alias
} else := "FR [JORF]" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "anssifrp256v1",
        "frp256v1"
    }

    normalized == alias
} else := "unknown"

#
# ---------------------------------------------------------
# Helper: get_eccg_canonical_ec_curve_or_unknown
#
# Purpose:
# Map registry/library aliases to the canonical curve names used
# in the ECCG table.
#
# ECCG canonical names:
# - BrainpoolP256r1
# - BrainpoolP384r1
# - BrainpoolP512r1
# - NIST P-256
# - NIST P-384
# - NIST P-521
# - FRP256v1
# ---------------------------------------------------------
#
get_eccg_canonical_ec_curve_or_unknown(curve) := "BrainpoolP256r1" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "brainpoolbrainpoolp256r1",
        "brainpoolp256r1"
    }

    normalized == alias
} else := "BrainpoolP384r1" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "brainpoolbrainpoolp384r1",
        "brainpoolp384r1"
    }

    normalized == alias
} else := "BrainpoolP512r1" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "brainpoolbrainpoolp512r1",
        "brainpoolp512r1"
    }

    normalized == alias
} else := "NIST P-256" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "nistp256",
        "p256",
        "secgsecp256r1",
        "secp256r1",
        "x962prime256v1",
        "prime256v1"
    }

    normalized == alias
} else := "NIST P-384" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "nistp384",
        "p384",
        "secgsecp384r1",
        "secp384r1"
    }

    normalized == alias
} else := "NIST P-521" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "nistp521",
        "p521",
        "secgsecp521r1",
        "secp521r1"
    }

    normalized == alias
} else := "FRP256v1" if {
    normalized := normalize_ec_curve_name(curve)

    some alias in {
        "anssifrp256v1",
        "frp256v1"
    }

    normalized == alias
} else := "unknown"

#
# ---------------------------------------------------------
# Helper: is_eccg_nist_special_p_curve
#
# Purpose:
# Identify ECCG-recommended NIST prime curves that are subject
# to ECCG note 39-SpecialP.
#
# ECCG context:
# In the EC-DLOG parameter table, the following NIST curves are
# recommended, but are associated with the specific note:
#
#   - NIST P-256
#   - NIST P-384
#   - NIST P-521
#
# ECCG note:
# - 39-SpecialP
#
# Rationale:
# The prime number p used by these curves has a special form.
# ECCG notes that this can make side-channel attacks more efficient
# than with a random prime, and not only because finite-field
# arithmetic is faster.
#
# Detection strategy:
# - First normalize/map the input curve identifier to the canonical
#   ECCG curve name using get_eccg_canonical_ec_curve_or_unknown().
# - Then check whether the canonical curve is one of the NIST curves
#   that carry the SpecialP note.
#
# Examples matched:
# - nist/P-256
# - secg/secp256r1
# - x962/prime256v1
# - nist/P-384
# - secg/secp384r1
# - nist/P-521
# - secg/secp521r1
#
# Notes:
# - This helper does not determine whether a curve is recommended.
#   Use is_eccg_recommended_ec_curve() for recommendation status.
# - This helper only indicates whether note 39-SpecialP should be
#   attached to the finding.
# ---------------------------------------------------------
#
is_eccg_nist_special_p_curve(curve) if {
    canonical := get_eccg_canonical_ec_curve_or_unknown(curve)

    some c in {
        "NIST P-256",
        "NIST P-384",
        "NIST P-521"
    }

    canonical == c
}
