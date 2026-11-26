package cbom.eccg.symmetric_constructions.key_combiners

import rego.v1

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.classifying_helpers.is_key_establishment_primitive
import data.cbom.eccg.classifying_helpers.is_combiner_primitive

import data.cbom.eccg.getter_helpers.get_component_evidence_occurrences_or_empty
import data.cbom.eccg.getter_helpers.get_component_occurrence_location_or_empty
import data.cbom.eccg.getter_helpers.get_component_bom_ref_or_empty

import data.cbom.eccg.symmetric_constructions.key_combiners.helpers.has_combination_related_dependency
import data.cbom.eccg.symmetric_constructions.key_combiners.helpers.has_hybrid_establishment_dependencies
import data.cbom.eccg.symmetric_constructions.key_combiners.helpers.is_combination_related_primitive

SECTION := "Symmetric-Constructions"
SUBSECTION := "Key-Combiners"

# No warnings means no issues detected by these heuristics.
# It does not prove cryptographic compliance.
default compliant := false

compliant if {
    count(findings) == 0
}


# ------------------------------------------------------------
# ECCG-KC-001
# Potential hybrid key combiner through dependencies.
#
# Detects:
# 1. At least two key-establishment dependencies.
# 2. At least one combining-related dependency.
#
# Does not distinguish CatKDF, CasKDF or NIST combiners.
# ------------------------------------------------------------
findings contains finding if {
    some component in input.components

    has_hybrid_establishment_dependencies(component)
    has_combination_related_dependency(component)

    finding := build_finding(
        "ECCG-KC-001",
        "warning",
        "Potential hybrid key combiner detected through dependencies. Verify compliance with ECCG Section 3.9.",
        component,
        {
            "status": "combiner_unverified",
            "method": "dependencies",
            "heuristic": true
        }
    )
}


# ------------------------------------------------------------
# ECCG-KC-001
# Potential hybrid key combiner through occurrences.
#
# Independent of dependency information.
#
# Detects:
# 1. Two key-establishment cryptographic assets.
# 2. A combining-related cryptographic asset.
# 3. All three appearing in the same source file.
#
# Same-file co-occurrence does not prove key combination.
# ------------------------------------------------------------
findings contains finding if {
    some i, establishment_a in input.components
    some j, establishment_b in input.components
    i < j

    is_key_establishment_primitive(establishment_a)
    is_key_establishment_primitive(establishment_b)

    some combining in input.components
    is_combination_related_primitive(combining)

    some occ_a in get_component_evidence_occurrences_or_empty(establishment_a)
    some occ_b in get_component_evidence_occurrences_or_empty(establishment_b)
    some occ_c in get_component_evidence_occurrences_or_empty(combining)

    file := get_component_occurrence_location_or_empty(occ_a)
    file != ""

    file == get_component_occurrence_location_or_empty(occ_b)
    file == get_component_occurrence_location_or_empty(occ_c)

    finding := build_finding(
        "ECCG-KC-001",
        "warning",
        "Potential hybrid key combiner detected through source-code occurrences. Verify compliance with ECCG Section 3.9.",
        combining,
        {
            "status": "combiner_unverified",
            "method": "occurrences_same_file",
            "sharedFile": file,
            "establishmentA": get_component_bom_ref_or_empty(establishment_a),
            "establishmentB": get_component_bom_ref_or_empty(establishment_b),
            "heuristic": true
        }
    )
}


# ------------------------------------------------------------
# ECCG-KC-001
# Generic cryptographic combiner detected.
#
# CycloneDX identifies a combiner primitive but cannot
# establish its actual construction.
#
# ECCG accepts NIST SP 800-227 combiners, CatKDF and CasKDF.
# An unknown combiner requires review, not automatic rejection.
# ------------------------------------------------------------
findings contains finding if {
    some component in input.components

    is_combiner_primitive(component)

    finding := build_finding(
        "ECCG-KC-001",
        "warning",
        "Cryptographic combiner detected, but the construction cannot be verified against ECCG Section 3.9.",
        component,
        {
            "status": "combiner_scheme_unverified",
            "method": "declared_combiner_primitive",
            "heuristic": true
        }
    )
}

