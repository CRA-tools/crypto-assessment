package cbom.eccg.getter_helpers

import data.cbom.eccg.relationship_helpers.depends_on_component
import data.cbom.eccg.relationship_helpers.component_matches_primitive
import data.cbom.eccg.relationship_helpers.components_share_evidence_location_and_line
import data.cbom.eccg.relationship_helpers.components_share_same_source_file


#
# Helper: retrieve a note by its ID from the shared notes dataset.
#
# Loaded from:
# policies/eccg/eccg_notes.json
#
# Actual OPA path:
# data.eccg.eccg_notes.notes["Symmetric-Constructions"]["6-AddIntegrity"]
#
get_note(section, subsection, note_string_id) := note if {
    note := data.notes[section][subsection][note_string_id]
} else := {
    "title": "unknown",
    "text": "Note not found"
}

# Convention: algorithm names, families, curves, parameter identifiers and
# enum strings return lower(trim_space(value)); punctuation is preserved.
# OIDs, references, file paths and source context are trimmed without changing
# case. Object, array and numeric getters retain their existing return types.
# Callers do not need to repeat lower/trim_space on normalized getter results.
get_component_name_or_empty(component) := lower(trim_space(name)) if {
    name := object.get(component, "name", "")
    is_string(name)
    name != ""
} else := ""

get_component_bom_ref_or_empty(component) := trim_space(bom_ref) if {
    bom_ref := object.get(component, "bom-ref", "")
    is_string(bom_ref)
    bom_ref != ""
} else := ""

get_component_additional_context_or_empty(component) := trim_space(additional_context) if {
    additional_context := object.get(component, "additionalContext", "")
    is_string(additional_context)
    additional_context != ""
} else := ""


# Retrieve the dependency entry associated with a specific component.
#
# This helper obtains the component's "bom-ref" and searches the CBOM's
# top-level "dependencies" array for an entry whose "ref" matches it.
#
# Example:
#   Component:
#     {"bom-ref": "hybrid-kdf", "name": "Hybrid Key Derivation"}
#
#   CBOM dependencies:
#     [
#       {
#         "ref": "hybrid-kdf",
#         "dependsOn": ["hkdf", "hmac"]
#       },
#       {
#         "ref": "hkdf",
#         "dependsOn": []
#       }
#     ]
#
#   get_component_dependency(component)
#     => {
#          "ref": "hybrid-kdf",
#          "dependsOn": ["hkdf", "hmac"]
#        }
#
# Returns an empty object ({}) if the component has no "bom-ref",
# no matching dependency entry exists, or the dependencies field
# is missing or is not an array.
#
# Note: The helper returns the complete dependency entry, not just
# the "dependsOn" references. It assumes at most one matching entry
# exists for each component's "bom-ref".
get_component_dependency(component) := dependency if {
    bom_ref := get_component_bom_ref_or_empty(component)
    bom_ref != ""

    dependencies := object.get(input, "dependencies", [])
    is_array(dependencies)

    some dependency in dependencies
    is_object(dependency)

    dep_ref := object.get(dependency, "ref", "")
    is_string(dep_ref)
    trim_space(dep_ref) == bom_ref
} else := {}

# Retrieve the bom-ref values of a component's direct dependencies.
#
# This helper looks up the component's dependency entry in the CBOM
# and extracts the "dependsOn" array.
#
# Example:
#   Component:
#     {"bom-ref": "hybrid-kdf", "name": "Hybrid Key Derivation"}
#
#   CBOM dependencies:
#     {
#       "ref": "hybrid-kdf",
#       "dependsOn": ["hkdf", "hmac"]
#     }
#
#   get_component_dependency_refs_or_empty(component)
#     => ["hkdf", "hmac"]
#
# Returns an empty array if the component has no dependency entry
# or if the "dependsOn" field is missing or is not an array.
#
# References are trimmed; blank and non-string entries are ignored.
# Note: Only direct dependencies are returned, not transitive ones.
get_component_dependency_refs_or_empty(component) := refs if {
    dependency := get_component_dependency(component)

    raw_refs := object.get(dependency, "dependsOn", [])
    is_array(raw_refs)
    refs := [trim_space(ref) |
        some ref in raw_refs
        is_string(ref)
        trim_space(ref) != ""
    ]
} else := []

# Resolve a component's direct dependency references into component objects.
#
# This helper uses get_component_dependency_refs_or_empty() to retrieve
# the dependency bom-refs, then searches input.components for matching
# component objects.
#
# Example:
#   CBOM components:
#     [
#       {"bom-ref": "hybrid-kdf", "name": "Hybrid Key Derivation"},
#       {"bom-ref": "hkdf", "name": "HKDF"},
#       {"bom-ref": "hmac", "name": "HMAC"}
#     ]
#
#   CBOM dependencies:
#     {
#       "ref": "hybrid-kdf",
#       "dependsOn": ["hkdf", "hmac"]
#     }
#
#   get_component_dependency_components_or_empty(hybrid_component)
#     => [
#          {"bom-ref": "hkdf", "name": "HKDF"},
#          {"bom-ref": "hmac", "name": "HMAC"}
#        ]
#
# Returns an empty array if no dependency components can be resolved.
# Dependency references without matching entries in input.components
# are ignored.
#
# Note: Only direct dependencies are resolved, not transitive ones.
get_component_dependency_components_or_empty(component) := results if {
    refs := get_component_dependency_refs_or_empty(component)

    components := object.get(input, "components", [])

    results := [dep_component |
        some ref in refs
        some dep_component in components

        get_component_bom_ref_or_empty(dep_component) == ref
    ]
}

get_component_related_crypto_material_properties_or_empty(component) := related_crypto_material_properties if {
    crypto_properties := get_component_crypto_properties_or_empty(component)
    related_crypto_material_properties := object.get(crypto_properties, "relatedCryptoMaterialProperties", {})
    is_object(related_crypto_material_properties)
    related_crypto_material_properties != {}
} else := {}

get_related_crypto_material_type_or_empty(component) := lower(trim_space(type)) if {
    related_crypto_material_properties := get_component_related_crypto_material_properties_or_empty(component)
    related_crypto_material_properties != {}

    type := object.get(related_crypto_material_properties, "type", "")
    is_string(type)
    type != ""
} else := ""

get_related_crypto_material_size_or_negative_one(component) := size if {
    related_crypto_material_properties := get_component_related_crypto_material_properties_or_empty(component)
    related_crypto_material_properties != {}

    size := object.get(related_crypto_material_properties, "size", -1)
    is_number(size)
    size != -1
} else := -1

get_component_crypto_properties_or_empty(component) := crypto_properties if {
    crypto_properties := object.get(component, "cryptoProperties", {})
    is_object(crypto_properties)
    crypto_properties != {}
} else := {}


get_component_asset_type_or_empty(component) := lower(trim_space(asset_type)) if {
    crypto_properties := get_component_crypto_properties_or_empty(component)
    crypto_properties != {}

    asset_type := object.get(crypto_properties, "assetType",  "")
    is_string(asset_type)
    asset_type != ""
} else := ""

get_component_oid_or_empty(component) := trim_space(oid) if {
    crypto_properties := get_component_crypto_properties_or_empty(component)
    crypto_properties != {}

    oid := object.get(crypto_properties, "oid", "")
    is_string(oid)
    oid != ""
} else := ""

get_component_algorithm_properties_or_empty(component) := algorithm_properties if {
    crypto_properties := get_component_crypto_properties_or_empty(component)
    crypto_properties != {}

    algorithm_properties := object.get(crypto_properties, "algorithmProperties", {})
    is_object(algorithm_properties)
    algorithm_properties != {}
} else := {}

# Prefer the registry field ellipticCurve, then the older curve field emitted
# by CBOMkit. Blank or malformed values allow fallback; an explicit nonempty
# string remains authoritative even when the curve is not agreed.
get_component_elliptic_curve_or_empty(component) := lower(trim_space(elliptic_curve)) if {
    algorithm_properties := get_component_algorithm_properties_or_empty(component)
    algorithm_properties != {}

    elliptic_curve := object.get(algorithm_properties, "ellipticCurve", "")
    is_string(elliptic_curve)
    trim_space(elliptic_curve) != ""
} else := lower(trim_space(curve)) if {
    algorithm_properties := get_component_algorithm_properties_or_empty(component)
    algorithm_properties != {}

    curve := object.get(algorithm_properties, "curve", "")
    is_string(curve)
    trim_space(curve) != ""
} else := ""

get_component_algorithm_family_or_empty(component) := lower(trim_space(algorithm_family)) if {
    crypto_properties := get_component_algorithm_properties_or_empty(component)
    crypto_properties != {}

    algorithm_family := object.get(crypto_properties, "algorithmFamily", "")
    is_string(algorithm_family)
    algorithm_family != ""
} else := ""



get_component_primitive_or_empty(component) := lower(trim_space(primitive)) if {
    algorithm_properties := get_component_algorithm_properties_or_empty(component)
    algorithm_properties != {}

    primitive := object.get(algorithm_properties, "primitive", "")
    is_string(primitive)
    primitive != ""
} else := ""

# Return normalized functions as an array; accept a legacy scalar as one item.
get_component_crypto_function_or_empty(component) := crypto_functions if {
    algorithm_properties := get_component_algorithm_properties_or_empty(component)
    raw := object.get(algorithm_properties, "cryptoFunctions", [])
    is_array(raw)
    crypto_functions := [lower(trim_space(fn)) |
        some fn in raw
        is_string(fn)
        trim_space(fn) != ""
    ]
} else := [lower(trim_space(crypto_function))] if {
    algorithm_properties := get_component_algorithm_properties_or_empty(component)
    crypto_function := object.get(algorithm_properties, "cryptoFunctions", "")
    is_string(crypto_function)
    trim_space(crypto_function) != ""
} else := []


get_component_mode_or_empty(component) := lower(trim_space(mode)) if {
    algorithm_properties := get_component_algorithm_properties_or_empty(component)
    algorithm_properties != {}

    mode := object.get(algorithm_properties, "mode", "")
    is_string(mode)
    mode != ""
} else := ""

get_component_parameter_set_identifier_or_empty(component) := lower(trim_space(parameter_set_identifier)) if {
    algorithm_properties := get_component_algorithm_properties_or_empty(component)
    algorithm_properties != {}

    parameter_set_identifier := object.get(algorithm_properties, "parameterSetIdentifier", "")
    is_string(parameter_set_identifier)
    parameter_set_identifier != ""
} else := ""

get_component_parameter_set_identifier_to_number_or_negative_one(component) := parameter_set_identifier_number if {
    raw := get_component_parameter_set_identifier_or_empty(component)
    raw != ""
    parameter_set_identifier_number := to_number(raw)
} else := -1

get_component_evidence_or_empty(component) := evidence if {
    evidence := object.get(component, "evidence", {})
    is_object(evidence)
    evidence != {}
} else := {}

get_component_evidence_occurrences_or_empty(component) := occurrences if {
    evidence := get_component_evidence_or_empty(component)
    evidence != {}

    occurrences := object.get(evidence, "occurrences", [])
    is_array(occurrences)
    occurrences != []
} else := []

get_component_by_bomref(bom_ref) := component if {
    is_string(bom_ref)
    ref := trim_space(bom_ref)
    ref != ""
    some i
    component := input.components[i]
    get_component_bom_ref_or_empty(component) == ref
}

get_component_occurrence_location_or_empty(occurrence) := trim_space(location) if {
    location := object.get(occurrence, "location", "")
    is_string(location)
    location != ""
} else := ""

get_component_occurrence_line_or_negative_one(occurrence) := line if {
    line := object.get(occurrence, "line", -1)
    is_number(line)
    line != -1
} else  := -1

get_component_occurrence_offset_or_negative_one(occurrence) := offset if {
    offset := object.get(occurrence, "offset", -1)
    is_number(offset)
    offset != -1
} else := -1

get_component_occurrence_additional_context_or_empty(occurrence) := trim_space(additional_context) if {
    additional_context := object.get(occurrence, "additionalContext", "")
    is_string(additional_context)
    additional_context != ""
} else := ""

get_dependency_components_by_primitive(parent_component, primitive) := candidates if {
    candidates := [
        candidate |
        some i
        candidate := input.components[i]
        component_matches_primitive(candidate, primitive)
        depends_on_component(parent_component, candidate)
    ]
}

get_shared_source_file_or_empty(component_a, component_b) := location if {
    shared_locations := get_components_shared_source_files(component_a, component_b)
    count(shared_locations) > 0

    sorted_locations := sort(shared_locations)
    location := sorted_locations[0]
    is_string(location)
    location != ""
} else := ""

#
# ---------------------------------------------------------
# Helper: get_related_components_by_primitive
#
# Return all components related to a parent component, constrained
# by the expected primitive type of the candidate component.
#
# Strategy:
# 1. Prefer explicit CBOM dependency relationships.
# 2. If no dependency candidates exist, fall back to same file+line co-location.
# ---------------------------------------------------------
#
get_related_components_by_primitive(parent_component, candidate_primitive) := candidates if {

    dependency_candidates := get_dependency_components_by_primitive(parent_component, candidate_primitive)
    count(dependency_candidates) > 0

    candidates := dependency_candidates
} else := candidates if {

    dependency_candidates := get_dependency_components_by_primitive(parent_component, candidate_primitive)
    count(dependency_candidates) == 0

    candidates := [
        candidate |
        some i
        candidate := input.components[i]
        component_matches_primitive(candidate, candidate_primitive)
        components_share_evidence_location_and_line(parent_component, candidate)
    ]
}

#
# ---------------------------------------------------------
# Helper: get_related_component_by_primitive
#
# Compatibility wrapper.
# Return one deterministic related component.
# Prefer get_related_components_by_primitive(...) for new rules.
# ---------------------------------------------------------
#
get_related_component_by_primitive(parent_component, candidate_primitive) := candidate_component if {
    candidates := get_related_components_by_primitive(parent_component, candidate_primitive)
    count(candidates) > 0

    sorted_candidates := sort(candidates)
    candidate_component := sorted_candidates[0]
}

#
# Return a schema-shaped text string containing the common fields used to
# identify a cryptographic algorithm across scanner outputs.
#
# Uses only CycloneDX algorithmProperties fields:
# - primitive
# - algorithmFamily
# - parameterSetIdentifier
# - ellipticCurve
# - curve (deprecated)
#
get_component_algorithm_identifier_text(component) := text if {
    identifiers := [
        get_component_name_or_empty(component),
        get_component_primitive_or_empty(component),
        get_component_algorithm_family_or_empty(component),
        get_component_parameter_set_identifier_or_empty(component),
        get_component_elliptic_curve_or_empty(component),
    ]
    text := concat(" ", [identifier | some identifier in identifiers; identifier != ""])
}

get_components_shared_source_files(component_a, component_b) := shared_locations if {
    shared_locations := {
        location |
        some occurrence_a in get_component_evidence_occurrences_or_empty(component_a)
        some occurrence_b in get_component_evidence_occurrences_or_empty(component_b)

        location_a := get_component_occurrence_location_or_empty(occurrence_a)
        location_b := get_component_occurrence_location_or_empty(occurrence_b)

        location_a != ""
        location_b != ""

        location_a == location_b
        location := location_a
    }
}


get_components_shared_source_location_and_line_or_unknown(component_a, component_b) := match if {
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

    match := {
        "location": location_a,
        "line": line_a
    }
} else := {
    "location": "unknown",
    "line": -1
}

get_composition_match_basis(component_a, component_b) := "same-line" if {
    components_share_evidence_location_and_line(component_a, component_b)
} else := "same-file" if {
    components_share_same_source_file(component_a, component_b)
} else := "no-match"

#
# ---------------------------------------------------------
# Helper: get_component_source_references_or_empty
#
# Return all source-code references for a component.
# Each entry keeps the file path, line number, offset,
# and additional context together.
#
# Return [] if no valid occurrences exist.
# ---------------------------------------------------------
#
get_component_source_references_or_empty(component) := source_references if {
    occurrences := get_component_evidence_occurrences_or_empty(component)

    source_references := [
        {
            "location": get_component_occurrence_location_or_empty(occurrence),
            "line": get_component_occurrence_line_or_negative_one(occurrence),
            "offset" : get_component_occurrence_offset_or_negative_one(occurrence),
            "additionalContext": get_component_occurrence_additional_context_or_empty(occurrence)
        }
        | some i
          occurrence := occurrences[i]
    ]
} else := []

#
# Return the first source file location recorded for a component.
#
# CBOM components can contain evidence occurrences that point back to
# source-code locations. This helper returns the "location" value from the
# first occurrence.
#
# If the component has no evidence occurrences, or if the location field is
# missing, this returns "unknown".
#
get_first_source_location_or_empty(component) := location if {
    occurrences := get_component_evidence_occurrences_or_empty(component)
    count(occurrences) > 0
    location := get_component_occurrence_location_or_empty(occurrences[0])
    location != ""
} else := ""

#
# Return the first source line recorded for a component.
#
# This helper reads the "line" value from the first evidence occurrence
# attached to the component.
#
# If the component has no evidence occurrences, or if the line field is
# missing, this returns -1.
#
get_first_source_line_or_negative_one(component) := line if {
    occurrences := get_component_evidence_occurrences_or_empty(component)
    count(occurrences) > 0
    line := get_component_occurrence_line_or_negative_one(occurrences[0])
    line != -1
} else := -1

#
# Return the algorithm component associated with a key-material component.
#
# CBOMkit may represent generated or related key material as a separate
# component with assetType = "related-crypto-material". The relationship
# between the key material and the algorithm is represented through the
# CycloneDX dependencies array.
#
# Example:
#
#   private-key@... dependsOn RSA-2048
#
# This helper follows that dependency edge and returns the related
# algorithm component, or {} if no such component is found.
#
get_related_algorithm_for_key_material_or_empty(key_component) := algorithm_component if {
    get_component_asset_type_or_empty(key_component) == "related-crypto-material"

    some algorithm_ref in get_component_dependency_refs_or_empty(key_component)

    algorithm_component := input.components[_]
    get_component_bom_ref_or_empty(algorithm_component) == algorithm_ref
    get_component_asset_type_or_empty(algorithm_component) == "algorithm"
} else := {}

#
# Return the name of the algorithm associated with a key-material component.
#
# This uses related_algorithm_for_key_material(...) to follow the CBOM
# dependency from the key-material component to its related algorithm.
#
# If no related algorithm can be found, this returns "unknown".
#
get_related_algorithm_name_for_key_or_empty(key_component) := name if {
    algorithm_component := get_related_algorithm_for_key_material_or_empty(key_component)
    name := get_component_name_or_empty(algorithm_component)
    name != ""
} else := ""

#
# Return the bom-ref of the algorithm associated with a key-material component.
#
# This is useful for including a stable reference to the related algorithm in
# finding metadata.
#
# If no related algorithm can be found, this returns "unknown".
#
get_related_algorithm_for_key_bom_ref_or_empty(key_component) := ref if {
    algorithm_component := get_related_algorithm_for_key_material_or_empty(key_component)
    ref := get_component_bom_ref_or_empty(algorithm_component)
    ref != ""
} else := ""

#
# Return the parameterSetIdentifier of the algorithm associated with
# a key-material component.
#
# For RSA key material, this often represents the RSA modulus size, for example:
#
#   "parameterSetIdentifier": "2048"
#
# This helper follows the dependency from the key-material component to the
# related algorithm component, then reads:
#
#   cryptoProperties.algorithmProperties.parameterSetIdentifier
#
# If no related algorithm or parameter set identifier can be found, this
# returns "unknown".
#
get_related_algorithm_for_key_parameter_set_or_empty(key_component) := parameter_set if {
    algorithm_component := get_related_algorithm_for_key_material_or_empty(key_component)
    parameter_set := get_component_parameter_set_identifier_or_empty(algorithm_component)
} else := ""

#
# Return standardized metadata for related cryptographic material.
#
# This is intended for components where:
#
#   cryptoProperties.assetType == "related-crypto-material"
#
# It captures the material type, size, related algorithm, bom-ref, and
# source-code evidence in one reusable object so private-key, public-key,
# secret-key, and other key-material rules can share the same finding shape.
#
get_related_crypto_material_finding_details(component) := details if {
    details := {
        "assetType": get_component_asset_type_or_empty(component),
        "materialType": get_related_crypto_material_type_or_empty(component),
        "size": get_related_crypto_material_size_or_negative_one(component),
        "relatedAlgorithm": get_related_algorithm_name_for_key_or_empty(component),
        "relatedAlgorithmBomRef": get_related_algorithm_for_key_bom_ref_or_empty(component),
        "relatedAlgorithmParameterSetIdentifier": get_related_algorithm_for_key_parameter_set_or_empty(component),
        "bomRef": get_component_bom_ref_or_empty(component),
        "sourceReferences": get_component_source_references_or_empty(component),
        "sourceLocation": get_first_source_location_or_empty(component),
        "sourceLine": get_first_source_line_or_negative_one(component)
    }
}

#
# ---------------------------------------------------------
# Helper: get_ec_curve_or_empty
#
# Purpose:
# Extract the elliptic curve identifier from a CBOM component.
#
# Detection order:
# 1. cryptoProperties.algorithmProperties.ellipticCurve
# 2. cryptoProperties.algorithmProperties.curve (legacy field)
# 3. cryptoProperties.algorithmProperties.parameterSetIdentifier
# 4. Recognizable curve token in component.name
#
# Rationale:
# CycloneDX 1.7 provides algorithmProperties.ellipticCurve and retains the
# deprecated curve field. The shared curve getter supports both locations.
#
# The component-name fallback intentionally extracts only known curve
# identifiers. A bare algorithm name such as "ECDH" is not a curve and should
# produce "" so the EC-DLOG policy can report an inconclusive finding.
# A parameter set naming multiple curves is inconclusive and must not be
# hidden by the component-name fallback. Non-curve parameters (e.g. "256")
# can still fall back to the name.
# ---------------------------------------------------------
#
get_ec_curve_or_empty(component) := curve if {
    curve := get_component_elliptic_curve_or_empty(component)
    curve != ""
} else := curve if {
    parameter := get_component_parameter_set_identifier_or_empty(component)
    count(get_ec_curve_matches(parameter)) > 0
    curve := get_ec_curve_from_text_or_empty(parameter)
} else := curve if {
    name := get_component_name_or_empty(component)
    name != ""
    curve := get_ec_curve_from_text_or_empty(name)
    curve != ""
} else := ""

#
# Extract one distinct known curve from text. Multiple aliases for the same
# curve are deduplicated; different curves, malformed input, and no match
# return an empty string. Recognition is independent of ECCG approval.
get_ec_curve_from_text_or_empty(text) := lower(curve) if {
    matches := get_ec_curve_matches(text)
    count(matches) == 1
    some curve in matches
} else := ""

# Preserve separators until after matching so identifiers such as secp256r10
# cannot match secp256r1. Each pattern is checked independently, including
# adjacent curve tokens that share a separator.
get_ec_curve_matches(text) := {curve |
    is_string(text)
    some curve, pattern in EC_CURVE_TEXT_PATTERNS
    bounded := sprintf("(?i)(^|[^[:alnum:]])(%s)($|[^[:alnum:]])", [pattern])
    regex.match(bounded, text)
}

# Text extraction patterns identify curves without assigning policy status.
# The getter adds token boundaries and rejects matches to multiple curves.
EC_CURVE_TEXT_PATTERNS := {
	"BrainpoolP256r1": "brainpool[[:space:]_./-]*p256r1",
	"BrainpoolP384r1": "brainpool[[:space:]_./-]*p384r1",
	"BrainpoolP512r1": "brainpool[[:space:]_./-]*p512r1",
	"FRP256v1": "frp256v1",
	"NIST P-256": "((nist[[:space:]_./-]*)?p[[:space:]_./-]*256|secp256r1|prime256v1)",
	"NIST P-384": "((nist[[:space:]_./-]*)?p[[:space:]_./-]*384|secp384r1)",
	"NIST P-521": "((nist[[:space:]_./-]*)?p[[:space:]_./-]*521|secp521r1)",
	"X25519": "x25519",
	"X448": "x448",
	"Ed25519": "(ed|edwards)25519",
	"Ed448": "(ed|edwards)448",
	"Curve25519": "curve25519",
	"Curve448": "curve448",
	"secp256k1": "secp256k1",
	"secp192r1": "((nist[[:space:]_./-]*)?p[[:space:]_./-]*192|secp192r1|prime192v1)",
	"secp224r1": "((nist[[:space:]_./-]*)?p[[:space:]_./-]*224|secp224r1)",
	"BrainpoolP160r1": "brainpool[[:space:]_./-]*p160r1",
	"BrainpoolP256t1": "brainpool[[:space:]_./-]*p256t1",
	"NIST B-283": "(nist[[:space:]_./-]*)?b[[:space:]_./-]*283",
	"NIST K-283": "(nist[[:space:]_./-]*)?k[[:space:]_./-]*283",
	"SM2": "sm2",
}
