package cbom.eccg.symmetric_constructions.key_combiners.helpers

import data.cbom.eccg.classifying_helpers.is_kdf_primitive
import data.cbom.eccg.classifying_helpers.is_combiner_primitive
import data.cbom.eccg.classifying_helpers.is_mac_primitive
import data.cbom.eccg.classifying_helpers.is_key_establishment_primitive
import data.cbom.eccg.classifying_helpers.is_hash_primitive

import data.cbom.eccg.getter_helpers.get_component_bom_ref_or_empty
import data.cbom.eccg.getter_helpers.get_component_dependency_components_or_empty
import data.cbom.eccg.getter_helpers.get_component_evidence_occurrences_or_empty
import data.cbom.eccg.getter_helpers.get_component_occurrence_location_or_empty
import data.cbom.eccg.getter_helpers.get_component_occurrence_line_or_negative_one


# Identify components potentially involved in combining secrets.
# Accept hashes and MACs as well as KDFs because approved NIST
# constructions need not appear as a dedicated KDF asset.
is_combination_related_primitive(component) if {
    is_kdf_primitive(component)
} else if {
    is_mac_primitive(component)
} else if {
    is_combiner_primitive(component)
} else if {
    is_hash_primitive(component)
}


# A potential hybrid construction has at least two distinct
# key-establishment assets among its direct dependencies.
#
# Example:
#   hybrid-kdf -> ECDH, ML-KEM, HKDF
#
# This establishes only a potential hybrid composition.
has_hybrid_establishment_dependencies(component) if {
    dependencies := get_component_dependency_components_or_empty(component)

    some i, component_a in dependencies
    some j, component_b in dependencies
    i < j

    is_key_establishment_primitive(component_a)
    is_key_establishment_primitive(component_b)
}

# Check whether a candidate hybrid component directly depends
# on a cryptographic operation that might combine secrets.
has_combination_related_dependency(component) if {
    dependencies := get_component_dependency_components_or_empty(component)

    some dep in dependencies
    is_combination_related_primitive(dep)
}



possible_cascade_through_dependencies(component) if {
    dependencies := get_component_dependency_components_or_empty(component)
    # At least one KDF dependency.
    some kdf in dependencies
    is_kdf_primitive(kdf)

    some mac in dependencies
    is_mac_primitive(mac)

    kdf["bom-ref"] != mac["bom-ref"]
}


kdf_occurrences(component) := results if {
    is_kdf_primitive(component)

    ref := get_component_bom_ref_or_empty(component)
    ref != ""

    results := {result |
        some i, occ in get_component_evidence_occurrences_or_empty(component)

        file := get_component_occurrence_location_or_empty(occ)
        file != ""

        line := get_component_occurrence_line_or_negative_one(occ)

        result := {
            "id": sprintf("%s:%d", [ref, i]),
            "bom_ref": ref,
            "file": file,
            "line": line
        }
    }
}



# Detect a potential cascade-based KDF construction
# through cryptographic dependencies.
#
# Conditions:
# 1. At least two key-establishment dependencies.
# 2. At least one KDF dependency.
# 3. At least one MAC dependency.
#
# This is only a heuristic, not proof of CasKDF.
possible_cascade_kdf(component) if {
    has_hybrid_establishment_dependencies(component)
    possible_cascade_through_dependencies(component)
}


# Detect potential multistage key derivation through
# source-code occurrences.
#
# Conditions:
# 1. At least two key-establishment dependencies.
# 2. At least two distinct KDF occurrences in the same file.
#
# The two occurrences may refer to the same KDF asset.
possible_cascade_kdf(component) if {
    has_hybrid_establishment_dependencies(component)

    dependencies := get_component_dependency_components_or_empty(component)

    some kdf_a in dependencies
    some kdf_b in dependencies

    is_kdf_primitive(kdf_a)
    is_kdf_primitive(kdf_b)

    matches := possible_multistage_kdf_occurrences(kdf_a, kdf_b)
    count(matches) > 0
}


# Return pairs of distinct KDF occurrences in the same file.
#
# Example:
#   HKDF occurrence at crypto.py:20
#   HKDF occurrence at crypto.py:35
#
# Returns a set describing the matching occurrence pairs.
#
# Note: Matching occurrences do not establish that the
# output of one KDF is used as input to another.
possible_multistage_kdf_occurrences(component_a, component_b) := results if {
    occurrences_a := kdf_occurrences(component_a)
    occurrences_b := kdf_occurrences(component_b)

    results := {result |
        some a in occurrences_a
        some b in occurrences_b

        # Different occurrences.
        a.id != b.id

        # Both occur in the same file.
        a.file == b.file

        # Normalize ordering to avoid duplicate pairs.
        ids := sort([a.id, b.id])

        result := {
            "assessment": "possible_multistage_kdf",
            "file": a.file,
            "occurrences": ids,
            "kdfs": sort([a.bom_ref, b.bom_ref]),
            "lines": sort([a.line, b.line])
        }
    }
}


# Detect a potential cascade-based hybrid KDF using only
# source-code occurrences, without requiring dependencies.
#
# Conditions:
# 1. Two distinct key-establishment cryptographic assets.
# 2. At least one KDF primitive.
# 3. At least one MAC primitive.
# 4. All four have occurrences in the same source file.
#
# Example:
#   crypto.py:
#     ECDH       line 10
#     ML-KEM     line 15
#     HMAC       line 25
#     HKDF       line 30
#
# This is a weak CasKDF heuristic. Same-file occurrences
# do not establish sequential derivation or chaining.
possible_cascade_through_occurrences contains result if {
    # Find two key-establishment components.
    some i, establishment_a in input.components
    some j, establishment_b in input.components
    i < j

    is_key_establishment_primitive(establishment_a)
    is_key_establishment_primitive(establishment_b)

    # Find KDF and MAC components.
    some kdf in input.components
    some mac in input.components

    is_kdf_primitive(kdf)
    is_mac_primitive(mac)

    # Retrieve source-code occurrences.
    some occ_a in get_component_evidence_occurrences_or_empty(establishment_a)
    some occ_b in get_component_evidence_occurrences_or_empty(establishment_b)
    some occ_kdf in get_component_evidence_occurrences_or_empty(kdf)
    some occ_mac in get_component_evidence_occurrences_or_empty(mac)

    # Require the same source file.
    file := get_component_occurrence_location_or_empty(occ_a)
    file != ""

    file == get_component_occurrence_location_or_empty(occ_b)
    file == get_component_occurrence_location_or_empty(occ_kdf)
    file == get_component_occurrence_location_or_empty(occ_mac)

    result := {
        "assessment": "possible_hybrid_prf_kdf_composition",
        "method": "occurrences",
        "file": file,
        "establishment_a": get_component_bom_ref_or_empty(establishment_a),
        "establishment_b": get_component_bom_ref_or_empty(establishment_b),
        "kdf": get_component_bom_ref_or_empty(kdf),
        "mac": get_component_bom_ref_or_empty(mac)
    }
}

