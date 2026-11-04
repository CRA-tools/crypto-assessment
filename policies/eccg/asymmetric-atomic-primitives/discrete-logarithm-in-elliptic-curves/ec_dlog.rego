package cbom.eccg.asymmetric_atomic_primitives.ec_dlog

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.getter_helpers.get_note

import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.eccg_recommended_ec_curve_labels
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_ecdlog_curve_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_eccg_canonical_ec_curve_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.get_eccg_ec_curve_family_or_empty
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.is_eccg_nist_special_p_curve
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.is_eccg_recommended_ec_curve
import data.cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.helpers.is_ecdlog_primitive

SECTION = "Asymmetric-Atomic-Primitives"
SUBSECTION = "EC-DLOG"

#
# ---------------------------------------------------------
# ECCG-ECDLOG-002
# EC-DLOG primitive uses an agreed NIST elliptic curve with
# SpecialP note.
#
# ECCG classification: R
#
# Applies to:
# - NIST P-256
# - NIST P-384
# - NIST P-521
#
# ECCG note:
# - 39-SpecialP
#
# Rationale:
# The NIST curves are recommended, but ECCG attaches a specific
# side-channel note because the prime p has a special form.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ecdlog_primitive(component)

    curve := get_ecdlog_curve_or_empty(component)
    curve != ""

    is_eccg_recommended_ec_curve(curve)
    is_eccg_nist_special_p_curve(curve)

    canonical_curve := get_eccg_canonical_ec_curve_or_empty(curve)
    curve_family := get_eccg_ec_curve_family_or_empty(curve)
    special_p_note := get_note(SECTION, SUBSECTION, "39-SpecialP")

    finding := build_finding(
        "ECCG-ECDLOG-002",
        "warning",
        sprintf(
            "EC-DLOG primitive detected with agreed NIST elliptic curve %s. Classified as recommended; ECCG note 39-SpecialP applies.",
            [canonical_curve]
        ),
        component,
        {
            "curve": canonical_curve,
            "curveFamily": curve_family,
            "note": special_p_note
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-ECDLOG-001
# EC-DLOG primitive uses an elliptic curve outside the agreed allowlist from EC-DLOG parameter table.
#
# ECCG classification: Not agreed / non-compliant / rejected
#
# Important:
# - This does NOT necessarily mean the curve is cryptographically unsafe.
# - It means the curve is not part of this rule's allowed parameter set.
#
# Examples of curves that may be valid elsewhere but are outside
# this rule's allowlist:
# - secp256k1
# - SM2
# - GOST curves
# - BLS / BN pairing curves
# - NIST binary curves B-* / K-*
#
# ECCG agreed curves are only:
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
findings contains finding if {
    component := input.components[_]

    is_ecdlog_primitive(component)

    curve := get_ecdlog_curve_or_empty(component)
    curve != ""

    not is_eccg_recommended_ec_curve(curve)

    finding := build_finding(
        "ECCG-ECDLOG-001",
        "critical",
        sprintf(
            "EC-DLOG primitive detected with elliptic curve %s, which is not allowed by ECCG-ECDLOG-001. Recommended curves: %s.",
            [curve, concat(", ", eccg_recommended_ec_curve_labels)]
        ),
        component,
        {
            "scheme": "EC-DLOG",
            "curve": curve,
            "allowedCurves": eccg_recommended_ec_curve_labels,
        }
    )
}

# A recognized EC primitive without an identifiable curve cannot be assessed.
# Keep missing data separate from a known curve outside the allowlist.
findings contains finding if {
    component := input.components[_]

    is_ecdlog_primitive(component)
    get_ecdlog_curve_or_empty(component) == ""

    finding := build_finding(
        "ECCG-ECDLOG-001",
        "warning",
        "EC-DLOG primitive detected, but its elliptic curve could not be determined. Supply algorithmProperties.ellipticCurve or algorithmProperties.curve to verify ECCG-ECDLOG-001.",
        component,
        {
            "scheme": "EC-DLOG",
            "curve": "",
            "allowedCurves": eccg_recommended_ec_curve_labels,
        }
    )
}

