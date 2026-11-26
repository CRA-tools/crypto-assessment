package cbom.eccg.test_type_helpers

# Runtime contracts for test fixtures. A predicate is true for the documented
# type and undefined otherwise. Enum membership and full CycloneDX schema
# validation remain the responsibility of the exported-fixture validator.

# Args: value: any Rego value.
# Returns: boolean true for an integer number; undefined otherwise.
is_integer(value) if {
	is_number(value)
	value == floor(value)
}

# Args: value: any Rego value.
# Returns: boolean true for object<string, any>; undefined otherwise.
# Locals: property_name: an object key, required to be a string.
is_string_keyed_object(value) if {
	is_object(value)
	every property_name in object.keys(value) {
		is_string(property_name)
	}
}

# Args: value: any Rego value, including intentionally malformed CBOM fields.
# Returns: boolean true for JSON-compatible values; undefined for sets or
#   objects with non-string keys, including when nested inside arrays/objects.
# Locals: nested_values: array<any>; nested_value: any Rego value;
#   nested_objects: array<object>; nested_object: object.
is_json_value(value) if {
	nested_values := [nested_value | walk(value, [_, nested_value])]
	every nested_value in nested_values {
		not is_set(nested_value)
	}
	nested_objects := [nested_value |
		some nested_value in nested_values
		is_object(nested_value)
	]
	every nested_object in nested_objects {
		is_string_keyed_object(nested_object)
	}
}

# Args: algorithm_properties: any Rego value.
# Returns: boolean true for an algorithm-properties object with correctly
#   typed identifier fields and cryptoFunctions; undefined otherwise.
# Locals: field_name: string; crypto_functions: array; crypto_function: any.
is_algorithm_properties(algorithm_properties) if {
	is_string_keyed_object(algorithm_properties)
	every field_name in {"primitive", "algorithmFamily", "mode", "padding", "ellipticCurve", "curve", "parameterSetIdentifier"} {
		is_string(object.get(algorithm_properties, field_name, ""))
	}
	crypto_functions := object.get(algorithm_properties, "cryptoFunctions", [])
	is_array(crypto_functions)
	every crypto_function in crypto_functions {
		is_string(crypto_function)
	}
}

# Args: source_occurrence: any Rego value.
# Returns: boolean true for an Occurrence object; undefined otherwise.
# Locals: line_number, source_offset: integer numbers after their guards.
is_occurrence(source_occurrence) if {
	is_string_keyed_object(source_occurrence)
	is_string(source_occurrence.location)
	line_number := object.get(source_occurrence, "line", 1)
	is_integer(line_number)
	line_number >= 1
	source_offset := object.get(source_occurrence, "offset", 0)
	is_integer(source_offset)
	source_offset >= 0
	is_string(object.get(source_occurrence, "additionalContext", ""))
}

# Args: source_reference: any Rego value.
# Returns: boolean true for a SourceReference object; undefined otherwise.
#   Missing source coordinates are represented by the integer sentinel -1.
is_source_reference(source_reference) if {
	is_string_keyed_object(source_reference)
	is_string(source_reference.location)
	is_integer(source_reference.line)
	source_reference.line >= -1
	is_integer(source_reference.offset)
	source_reference.offset >= -1
	is_string(source_reference.additionalContext)
}

# Args: input_component: any Rego value.
# Returns: boolean true for a Component object; undefined otherwise.
# Locals: evidence: object; occurrences: array; source_occurrence: object
#   after is_occurrence succeeds.
is_component(input_component) if {
	is_string_keyed_object(input_component)
	is_string(input_component.type)
	is_string(input_component["bom-ref"])
	is_string(input_component.name)
	is_string_keyed_object(object.get(input_component, "cryptoProperties", {}))
	evidence := object.get(input_component, "evidence", {})
	is_string_keyed_object(evidence)
	occurrences := object.get(evidence, "occurrences", [])
	is_array(occurrences)
	every source_occurrence in occurrences {
		is_occurrence(source_occurrence)
	}
}

# Args: input_component: any Rego value.
# Returns: boolean true for an AlgorithmComponent object; undefined otherwise.
is_algorithm_component(input_component) if {
	is_component(input_component)
	input_component.cryptoProperties.assetType == "algorithm"
	is_algorithm_properties(input_component.cryptoProperties.algorithmProperties)
	is_string(input_component.cryptoProperties.algorithmProperties.primitive)
	is_string(object.get(input_component.cryptoProperties, "oid", ""))
}

# Args: input_cbom: any Rego value.
# Returns: boolean true for the shared CBOM object shape; undefined otherwise.
# Locals: input_component: Component object after its guard succeeds.
is_cbom(input_cbom) if {
	is_string_keyed_object(input_cbom)
	is_string(input_cbom["$schema"])
	input_cbom.bomFormat == "CycloneDX"
	input_cbom.specVersion == "1.7"
	is_integer(input_cbom.version)
	input_cbom.version >= 1
	is_array(input_cbom.components)
	every input_component in input_cbom.components {
		is_component(input_component)
	}
}

# Args: finding: any Rego value.
# Returns: boolean true for a Finding object; undefined otherwise.
# Locals: field_name: string; source_reference: SourceReference object after
#   its guard succeeds. Additional policy metadata may have arbitrary types.
is_finding(finding) if {
	is_string_keyed_object(finding)
	every field_name in {"ruleId", "severity", "bomRef", "component", "message"} {
		is_string(finding[field_name])
	}
	is_array(finding.references)
	every source_reference in finding.references {
		is_source_reference(source_reference)
	}
}

# Args: actual_findings: any Rego value.
# Returns: boolean true for array<Finding> or set<Finding>; undefined otherwise.
# Locals: finding: Finding object after its guard succeeds.
is_findings(actual_findings) if {
	type_name(actual_findings) in {"array", "set"}
	every finding in actual_findings {
		is_finding(finding)
	}
}

# Args: test_case: any Rego value.
# Returns: boolean true for a TestCase object; undefined otherwise.
# Locals: expected_finding: object<string, any> after its guard succeeds.
is_test_case(test_case) if {
	is_string_keyed_object(test_case)
	is_string(test_case.name)
	is_cbom(test_case.input)
	is_array(test_case.expected)
	every expected_finding in test_case.expected {
		is_string_keyed_object(expected_finding)
	}
	is_integer(test_case.evaluationTime)
}
