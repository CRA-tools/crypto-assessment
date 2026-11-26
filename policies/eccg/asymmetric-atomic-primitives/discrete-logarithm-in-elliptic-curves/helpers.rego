package cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers

import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.BRAINPOOL_P256R1_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.BRAINPOOL_P384R1_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.BRAINPOOL_P512R1_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.NIST_P256_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.NIST_P384_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.NIST_P521_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.FRP256V1_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.CURVE25519_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.CURVE448_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.ED25519_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.ED448_CURVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.EC_DLOG_PRIMITIVE_FAMILIES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.EC_DLOG_PRIMITIVE_NAMES
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants.EC_DLOG_PRIMITIVE_OIDS

import data.cbom.eccg.classifying_helpers.is_key_agreement_primitive
import data.cbom.eccg.classifying_helpers.is_public_key_eccg_primitive

import data.cbom.eccg.general_helpers.normalize_crypto_identifier
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_asset_type_or_empty
import data.cbom.eccg.getter_helpers.get_component_elliptic_curve_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_or_empty
import data.cbom.eccg.getter_helpers.get_ec_curve_matches
import data.cbom.eccg.getter_helpers.get_ec_curve_or_empty

# Select the agreed curves here, composing their names from raw constants.
eccg_recommended_ec_curves := {
    "BrainpoolP256r1": {"family": "Brainpool [RFC5639]", "names": BRAINPOOL_P256R1_CURVE_NAMES},
    "BrainpoolP384r1": {"family": "Brainpool [RFC5639]", "names": BRAINPOOL_P384R1_CURVE_NAMES},
    "BrainpoolP512r1": {"family": "Brainpool [RFC5639]", "names": BRAINPOOL_P512R1_CURVE_NAMES},
    "NIST P-256": {"family": "NIST [FIPS186-4, Appendix D.1.2]", "names": NIST_P256_CURVE_NAMES},
    "NIST P-384": {"family": "NIST [FIPS186-4, Appendix D.1.2]", "names": NIST_P384_CURVE_NAMES},
    "NIST P-521": {"family": "NIST [FIPS186-4, Appendix D.1.2]", "names": NIST_P521_CURVE_NAMES},
    "FRP256v1": {"family": "FR [JORF]", "names": FRP256V1_CURVE_NAMES},
    # Group the corresponding Montgomery and Edwards forms under the table's
    # RFC7748 entries for curve assessment. Scheme policies remain separate.
    "Curve25519": {"family": "Edwards [RFC7748]", "names": CURVE25519_CURVE_NAMES | ED25519_CURVE_NAMES},
    "Curve448": {"family": "Edwards [RFC7748]", "names": CURVE448_CURVE_NAMES | ED448_CURVE_NAMES},
}

eccg_ec_curve_aliases := {normalize_crypto_identifier(alias): canonical |
    some canonical, properties in eccg_recommended_ec_curves
    some alias in properties.names
}

eccg_recommended_ec_curve_names := object.keys(eccg_ec_curve_aliases)

eccg_recommended_ec_curve_labels := sort(object.keys(eccg_recommended_ec_curves))

eccg_nist_special_p_curve_names := {normalize_crypto_identifier(name) |
    some name in ((NIST_P256_CURVE_NAMES | NIST_P384_CURVE_NAMES) | NIST_P521_CURVE_NAMES)
}

ecdlog_families := {normalize_crypto_identifier(family) |
    some family in EC_DLOG_PRIMITIVE_FAMILIES
}

ecdlog_names := {normalize_crypto_identifier(name) |
    some name in EC_DLOG_PRIMITIVE_NAMES
} | {normalize_crypto_identifier(name) |
    some name in (((CURVE25519_CURVE_NAMES | CURVE448_CURVE_NAMES) | ED25519_CURVE_NAMES) | ED448_CURVE_NAMES)
}

ecdlog_oid_values := {oid |
    some _, oid in EC_DLOG_PRIMITIVE_OIDS
}

# CycloneDX primitive categories narrow the candidates but do not establish
# EC usage. The shared classifiers cover pke, signature, kem, and key-agree.
is_ecdlog_candidate(component) if {
    get_component_asset_type_or_empty(component) in {"algorithm", "related-crypto-material"}
    is_public_key_eccg_primitive(component)
} else if {
    is_key_agreement_primitive(component)
}

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
# Detection order:
# - Require a pke, signature, kem, or key-agree primitive first.
# - Match cryptoProperties.oid against EC algorithm OIDs.
# - Fall back to algorithmProperties.algorithmFamily.
# - Fall back to component.name, including names with appended parameters.
# - Curve parameters are evaluated separately after classification.
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
    is_ecdlog_candidate(component)
    oid := get_component_oid_or_empty(component)
    oid in ecdlog_oid_values
} else if {
    is_ecdlog_candidate(component)
    family := get_component_algorithm_family_or_empty(component)
    normalize_crypto_identifier(family) in ecdlog_families
} else if {
    is_ecdlog_candidate(component)
    name := get_component_name_or_empty(component)
    is_ecdlog_name(name)
}

is_ecdlog_name(name) if {
    normalize_crypto_identifier(name) in ecdlog_names
} else if {
    some candidate in EC_DLOG_PRIMITIVE_NAMES
    pattern := sprintf(`(^|[-_ /])%s($|[-_ /])`, [lower(candidate)])
    regex.match(pattern, name)
}

# Preserve explicit curve metadata and recognized parameter sets, including
# ambiguity. X25519/X448 and Ed25519/Ed448 identify fixed curve parameters,
# so their OID or family can fill missing curve data.
# Generic EC OIDs and families do not establish a particular curve.
get_ecdlog_curve_or_empty(component) := curve if {
    curve := get_component_elliptic_curve_or_empty(component)
    curve != ""
} else := curve if {
    parameter := get_component_parameter_set_identifier_or_empty(component)
    count(get_ec_curve_matches(parameter)) > 0
    curve := get_ec_curve_or_empty(component)
} else := curve if {
    oid := get_component_oid_or_empty(component)
    some name, value in EC_DLOG_PRIMITIVE_OIDS
    oid == value
    curve := get_eccg_canonical_ec_curve_or_empty(name)
    curve in {"Curve25519", "Curve448"}
} else := curve if {
    family := get_component_algorithm_family_or_empty(component)
    curve := get_eccg_canonical_ec_curve_or_empty(family)
    curve in {"Curve25519", "Curve448"}
} else := curve if {
    curve := get_ec_curve_or_empty(component)
    curve != ""
} else := ""

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
# Edwards [RFC7748]
# - Curve25519 (including corresponding X25519/Ed25519 identifiers)
# - Curve448 (including corresponding X448/Ed448 identifiers)
#
# Important:
# - ECCG recommends the above named curves.
# - Other curves in the CycloneDX registry, such as BLS, BN,
#   secp256k1, binary NIST B/K curves, GOST, SM2, NUMS, and
#   miscellaneous curves, are not matched here.
# ---------------------------------------------------------
#
is_eccg_recommended_ec_curve(curve) if {
    normalized := normalize_crypto_identifier(curve)
    normalized in eccg_recommended_ec_curve_names
}


#
# ---------------------------------------------------------
# Helper: get_eccg_ec_curve_family_or_empty
#
# Purpose:
# Return the ECCG curve family for a recommended curve.
#
# Families from ECCG:
# - Brainpool [RFC5639]
# - NIST [FIPS186-4, Appendix D.1.2]
# - FR [JORF]
# - Edwards [RFC7748]
# ---------------------------------------------------------
#
get_eccg_ec_curve_family_or_empty(curve) := family if {
    canonical := get_eccg_canonical_ec_curve_or_empty(curve)
    family := eccg_recommended_ec_curves[canonical].family
} else := ""

#
# ---------------------------------------------------------
# Helper: get_eccg_canonical_ec_curve_or_empty
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
# - Curve25519
# - Curve448
# ---------------------------------------------------------
#
get_eccg_canonical_ec_curve_or_empty(curve) := canonical if {
    normalized := normalize_crypto_identifier(curve)
    canonical := eccg_ec_curve_aliases[normalized]
} else := ""

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
# - Normalize the input curve identifier, then match it against the
#   aliases constructed from the three NIST curve name constants.
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
    normalize_crypto_identifier(curve) in eccg_nist_special_p_curve_names
}
