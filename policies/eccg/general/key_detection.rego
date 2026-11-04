package cbom.eccg.general.key_detection

import data.cbom.eccg.classifying_helpers.is_private_key_material
import data.cbom.eccg.classifying_helpers.is_public_key_material

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_related_crypto_material_finding_details

#
# ---------------------------------------------------------
# ECCG-RSA-KEY-001
# Private key material detected.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_private_key_material(component)

    finding := build_finding(
        "ECCG-RSA-KEY-001",
        "high",
        sprintf(
            "Private key material '%s' was detected in the CBOM. Review whether this key is generated, embedded, stored, or otherwise exposed in the source context.",
            [get_component_name_or_empty(component)]
        ),
        component,
        get_related_crypto_material_finding_details(component)
    )
}

#
# ---------------------------------------------------------
# ECCG-RSA-KEY-002
# Public key material detected.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_public_key_material(component)

    finding := build_finding(
        "ECCG-RSA-KEY-002",
        "info",
        sprintf(
            "Public key material '%s' was detected in the CBOM. Public keys are not confidential, but should still be reviewed for lifecycle, trust, and algorithm-size policy.",
            [get_component_name_or_empty(component)]
        ),
        component,
        get_related_crypto_material_finding_details(component)
    )
}
