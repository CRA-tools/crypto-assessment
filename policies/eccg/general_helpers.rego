package cbom.eccg.general_helpers

import data.cbom.eccg.getter_helpers.get_component_source_references_or_empty
import data.cbom.eccg.getter_helpers.get_component_bom_ref_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_or_empty

import data.cbom.eccg.classifying_helpers.is_valid_severity

# Use the shared getter's normalization and empty-value convention.
has_parameter_set_identifier(component) if {
    get_component_parameter_set_identifier_or_empty(component) != ""
}

build_finding(rule_id, severity_level, message_text, component, extra_fields) := finding_object if {

    is_valid_severity(severity_level)
    
    name := get_component_name_or_empty(component)
    bom_ref := get_component_bom_ref_or_empty(component)
    references := get_component_source_references_or_empty(component)

    base_finding := {
        "ruleId": rule_id,
        "severity": severity_level,
        "message": message_text,
        "component": name,
        "bomRef": bom_ref,
        "references": references
    }

    finding_object := object.union(base_finding, extra_fields)
}

#
# ---------------------------------------------------------
# Helper: normalize_crypto_identifier
#
# Normalize cryptographic identifiers for consistent matching
# across different CBOM generators and naming conventions.
#
# Transformations:
# - Convert to lowercase
# - Remove whitespace
# - Remove hyphens, parentheses, slashes, underscores, dots,
#   and hash symbols
#
# Examples:
# - "SHA-256"       -> "sha256"
# - "SHA-512/256"   -> "sha512256"
# - "KMAC (256)"    -> "kmac256"
# - "KMACXOF(128)"  -> "kmacxof128"
# - "AES-256-GCM"   -> "aes256gcm"
#
# Normalization is intentionally lossy and intended for
# identifier matching, not reconstructing original names.
# ---------------------------------------------------------
#
normalize_crypto_identifier(name) := normalized if {
    lower_name := lower(name)
    normalized := regex.replace(
        lower_name,
        "[\\s()/_#.\\-\\\\]",
        ""
    )
}

matches_crypto_identifier(identifier, known_identifiers) if {
    normalized_identifier := normalize_crypto_identifier(identifier)
    some known_identifier in known_identifiers
    normalized_identifier == normalize_crypto_identifier(known_identifier)
}

matches_aes_construction_name(name, construction_pattern) if {
    normalized_name := normalize_crypto_identifier(name)
    pattern := sprintf(`^((aes[0-9]*)?(%s)|(%s)aes[0-9]*)$`, [construction_pattern, construction_pattern])
    regex.match(pattern, normalized_name)
} else if {
    pattern := sprintf(`^((aes([-_ /]?[0-9]+)?[-_ /])?(%s)|(%s)[-_ /]aes([-_ /]?[0-9]+)?)([-_ /](no|pkcs5|pkcs7|iso10126|zero)padding)?([-_ ][0-9]+){0,2}$`, [construction_pattern, construction_pattern])
    regex.match(pattern, lower(name))
}

#
# Return the policy evaluation timestamp in nanoseconds.
#
# Preferred deterministic input:
# {
#   "policyEvaluationDate": "2026-05-05T00:00:00Z"
# }
#
# Fallback:
# - wall-clock time from OPA.
#
evaluation_time_ns := ns if {
    date := input.policyEvaluationDate
    ns := time.parse_rfc3339_ns(date)
} else := ns if {
    ns := time.now_ns()
}

#
# Extract the year from the evaluation date.
#
evaluation_year := year if {
    parts := time.date(evaluation_time_ns)
    year := parts[0]
}

#
# Convert an ECCG legacy marker like L[2030] into a year.
#
legacy_marker_year(marker) := year if {
    is_string(marker)
    trimmed_marker := trim_space(marker)
    startswith(trimmed_marker, "L[")
    endswith(trimmed_marker, "]")

    year_text := trim_suffix(trim_prefix(marker, "L["), "]")
    year := to_number(year_text)
}

#
# Produce a status string for a legacy marker.
#
# Returns:
# - "legacy" if still inside the legacy period
# - "expired-legacy" if the legacy period has passed
#
legacy_marker_status(marker) := "legacy" if {
    is_legacy_marker_active(marker)
} else := "expired-legacy" if {
    is_legacy_marker_expired(marker)
}

legacy_status_severity(status) := "critical" if {
    status == "legacy"
} else := "error" if {
    status == "expired-legacy"
}

legacy_status_message(name, marker, status) := message if {
    status == "legacy"
    message := sprintf("%s is considered acceptable only as a legacy mechanism %s and should be phased out.", [name, marker])
} else := message if {
    status == "expired-legacy"
    message := sprintf("%s was acceptable only as a legacy mechanism %s, but that legacy period has expired.", [name, marker])
}

#
# Returns true when the current/evaluation year is less than or equal to
# the final accepted legacy year.
#
# Example:
#   is_legacy_until_year(2030)
#
# Means:
#   valid as legacy through calendar year 2030.
#
is_legacy_until_year(final_legacy_year) if {
    evaluation_year <= final_legacy_year
}

#
# Returns true once a legacy mechanism has expired.
#
# Example:
#   is_legacy_expired_after_year(2030)
#
# Means:
#   expired starting in 2031.
#
is_legacy_expired_after_year(final_legacy_year) if {
    evaluation_year > final_legacy_year
}

#
# True if the legacy marker is still active.
#
# Example:
#   is_legacy_marker_active("L[2030]")
#
is_legacy_marker_active(marker) if {
    year := legacy_marker_year(marker)
    is_legacy_until_year(year)
}

#
# True if the legacy marker has expired.
#
# Example:
#   is_legacy_marker_expired("L[2030]")
#
is_legacy_marker_expired(marker) if {
    year := legacy_marker_year(marker)
    is_legacy_expired_after_year(year)
}
