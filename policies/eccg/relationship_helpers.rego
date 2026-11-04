package cbom.eccg.relationship_helpers

import data.cbom.eccg.getter_helpers.get_component_evidence_occurrences_or_empty
import data.cbom.eccg.getter_helpers.get_component_occurrence_location_or_empty
import data.cbom.eccg.getter_helpers.get_component_occurrence_line_or_negative_one

import data.cbom.eccg.classifying_helpers.is_hash_primitive
import data.cbom.eccg.classifying_helpers.is_block_cipher_primitive
import data.cbom.eccg.classifying_helpers.is_mac_primitive
import data.cbom.eccg.classifying_helpers.is_ae_primitive
import data.cbom.eccg.classifying_helpers.is_kdf_primitive
import data.cbom.eccg.classifying_helpers.is_xof_primitive
import data.cbom.eccg.classifying_helpers.is_key_wrap_primitive
import data.cbom.eccg.classifying_helpers.is_combiner_primitive

components_share_same_source_file(component_a, component_b) if {
    some occurrence_a in get_component_evidence_occurrences_or_empty(component_a)
    some occurrence_b in get_component_evidence_occurrences_or_empty(component_b)

    location_a := get_component_occurrence_location_or_empty(occurrence_a)
    location_b := get_component_occurrence_location_or_empty(occurrence_b)

    location_a != ""
    location_b != "" 
    location_a == location_b
}

components_share_evidence_location_and_line(component_a, component_b) if {
    some occurrence_a in get_component_evidence_occurrences_or_empty(component_a)
    some occurrence_b in get_component_evidence_occurrences_or_empty(component_b)

    location_a := get_component_occurrence_location_or_empty(occurrence_a)
    line_a := get_component_occurrence_line_or_negative_one(occurrence_a)

    location_a != ""
    line_a != -1

    location_b := get_component_occurrence_location_or_empty(occurrence_b)
    line_b := get_component_occurrence_line_or_negative_one(occurrence_b)

    location_b != ""
    line_b != -1

    location_a == location_b
    line_a == line_b
}

depends_on_component(src_component, dst_component) if {
    some i
    dep := input.dependencies[i]
    dep.ref == src_component["bom-ref"]
    some j
    dep.dependsOn[j] == dst_component["bom-ref"]
}

#
# ---------------------------------------------------------
# Helper: components_share_evidence_location_within_lines
#
# Source-code proximity can suggest a relationship between
# cryptographic operations that are implemented together.
#
# Two components are considered co-located when their evidence
# points to the same source file and their line numbers differ
# by no more than the specified maximum distance.
#
# This is a heuristic relationship, not proof of cryptographic
# composition or data flow.
#
# ---------------------------------------------------------
#
components_share_evidence_location_within_lines(component_a, component_b, max_distance) if {
    is_number(max_distance)
    max_distance >= 0

    occurrences_a := get_component_evidence_occurrences_or_empty(component_a)
    occurrences_b := get_component_evidence_occurrences_or_empty(component_b)

    some occurrence_a in occurrences_a
    some occurrence_b in occurrences_b

    location_a := get_component_occurrence_location_or_empty(occurrence_a)
    location_b := get_component_occurrence_location_or_empty(occurrence_b)

    location_a != ""
    location_a == location_b

    line_a := get_component_occurrence_line_or_negative_one(occurrence_a)
    line_b := get_component_occurrence_line_or_negative_one(occurrence_b)

    line_a > 0
    line_b > 0

    distance := max([line_a, line_b]) - min([line_a, line_b])
    distance <= max_distance
}

component_has_evidence_in_window(component, location, start_line, end_line) if {
    some occurrence in get_component_evidence_occurrences_or_empty(component)

    occurrence_location := get_component_occurrence_location_or_empty(occurrence)
    occurrence_line := get_component_occurrence_line_or_negative_one(occurrence)

    occurrence_location == location
    occurrence_line >= start_line
    occurrence_line <= end_line
}

components_share_evidence_window(components, max_distance) if {
    is_array(components)
    count(components) >= 2

    is_number(max_distance)
    max_distance >= 0

    # Select an occurrence as the beginning of the window
    some component in components
    some occurrence in get_component_evidence_occurrences_or_empty(component)

    location := get_component_occurrence_location_or_empty(occurrence)
    start_line := get_component_occurrence_line_or_negative_one(occurrence)

    location != ""
    start_line > 0

    end_line := start_line + max_distance

    # Every component must have evidence inside this window
    every candidate in components {
        component_has_evidence_in_window(candidate, location, start_line, end_line)
    }
}

#
# ---------------------------------------------------------
# Helper: component_has_evidence_path_containing
#
# Purpose:
# Check whether a component has at least one evidence occurrence
# whose source file path contains a given substring.
#
# Strategy:
# - Iterate over all evidence occurrences attached to the component.
# - Extract the "location" field (file path).
# - Perform a case-insensitive substring match.
#
# Notes:
# - Matching is case-insensitive.
# - Only the file path is considered (line numbers are ignored).
# - Returns true on the first matching occurrence.
# - Returns false if no occurrences exist or no match is found.
#
# Example:
# component_has_evidence_path_containing(component, "test")
# → true if any occurrence path contains "test"
#
# Use cases:
# - Heuristic classification (e.g., test code vs production code)
# - Filtering findings based on file location
# - Context-aware policy rules
# ---------------------------------------------------------
#
component_has_evidence_path_containing(component, needle) if {
    occurrences := get_component_evidence_occurrences_or_empty(component)
    occurrences != []

    some occurrence in occurrences

    loc := get_component_occurrence_location_or_empty(occurrence)
    loc != ""

    contains(loc, needle)
}

#
# ---------------------------------------------------------
# Helper: component_matches_primitive
#
# True if a component matches the requested abstract kind.
# Extend this helper as new component kinds are needed.
# ---------------------------------------------------------
#
component_matches_primitive(component, kind) if {
    kind == "hash"
    is_hash_primitive(component)
} else if {
    kind == "block-cipher"
    is_block_cipher_primitive(component)
} else if {
    kind == "mac"
    is_mac_primitive(component)
} else if {
    kind == "ae"
    is_ae_primitive(component)
} else if {
    kind == "kdf"
    is_kdf_primitive(component)
} else if {
    kind == "xof"
    is_xof_primitive(component)
} else if {
    kind == "key-wrap"
    is_key_wrap_primitive(component)
} else if {
    kind == "combiner"
    is_combiner_primitive(component)
}
