package cbom.eccg.test_type_helpers_test

import data.cbom.eccg.asymmetric_atomic_primitives.ec_dlog_test as ec_helpers
import data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization_test as rsa_helpers
import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes_test as encryption_helpers
import data.cbom.eccg.asymmetric_constructions.digital_signatures_test as signature_helpers
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation_test as establishment_helpers
import data.cbom.eccg.cyclonedx_test_helpers as fixture_helpers
import data.cbom.eccg.getter_helpers_test as getter_helpers
import data.cbom.eccg.oid_constants_test as oid_helpers
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator_test as drbg_helpers
import data.cbom.eccg.test_type_helpers as test_types

# Type: AlgorithmComponent object, used only to exercise helper contracts.
valid_component := fixture_helpers.algorithm("Example", "hash", {})

# Type: Finding object. This synthetic identifier is not an ECCG policy rule.
valid_finding := {
	"ruleId": "helper-contract",
	"severity": "warning",
	"bomRef": "algorithm-under-test",
	"component": "example",
	"message": "Helper contract finding",
	"references": [],
}

# Strings, arrays, and objects must not masquerade as integer coordinates.
test_source_line_requires_a_positive_integer if {
	every invalid_line in [null, true, "1", [], {}, set(), -1, 0, 1.5] {
		not fixture_helpers.with_occurrence(valid_component, "src/example.py", invalid_line)
	}
	component_with_source := fixture_helpers.with_occurrence(valid_component, "src/example.py", 1)
	fixture_helpers.source_references(component_with_source) == [{
		"location": "src/example.py", "line": 1, "offset": -1, "additionalContext": "",
	}]
}

# Strict fixture parameters declared as strings reject every other value type.
test_fixture_string_parameters_reject_other_types if {
	every invalid_string in [null, true, 7, [], {}, set()] {
		not fixture_helpers.algorithm(invalid_string, "hash", {})
		not fixture_helpers.algorithm("Example", invalid_string, {})
		not fixture_helpers.with_oid(valid_component, invalid_string)
		not fixture_helpers.with_ref(valid_component, invalid_string)
		not fixture_helpers.with_occurrence(valid_component, invalid_string, 1)
		not fixture_helpers.case(invalid_string, [], [])
	}
}

# Arrays are required for component/expectation collections even when empty.
# An undefined constructor must not manufacture a seemingly valid empty BOM.
test_fixture_collections_require_arrays_of_objects if {
	every invalid_collection in [null, true, 7, "", {}, set()] {
		not fixture_helpers.bom(invalid_collection)
		not fixture_helpers.case("invalid components", invalid_collection, [])
		not fixture_helpers.case("invalid expectations", [], invalid_collection)
	}
	every invalid_entry in [null, true, 7, "", [], set(), {7: "non-string key"}] {
		not fixture_helpers.bom([invalid_entry])
		not fixture_helpers.case("invalid component entry", [invalid_entry], [])
		not fixture_helpers.case("invalid expected finding", [], [invalid_entry])
	}
	fixture_helpers.bom([]).components == []
	fixture_helpers.case("empty", [], []).expected == []
}

# Known algorithm fields have types, even when their values are supplied through
# the optional properties override rather than positional parameters.
test_algorithm_properties_preserve_field_types if {
	every invalid_properties in [null, true, 7, "", [], set(), {7: "non-string key"}] {
		not fixture_helpers.algorithm("Example", "hash", invalid_properties)
	}
	every field_name in ["primitive", "algorithmFamily", "parameterSetIdentifier", "ellipticCurve", "curve", "mode", "padding"] {
		every invalid_string in [null, 7, [], {}] {
			not fixture_helpers.algorithm("Example", "hash", {field_name: invalid_string})
		}
	}
	every invalid_functions in [null, "sign", {}, set(), ["sign", 7]] {
		not fixture_helpers.algorithm("Example", "hash", {"cryptoFunctions": invalid_functions})
	}
	fixture_helpers.algorithm("Example", "hash", {"cryptoFunctions": ["sign"]}).cryptoProperties.algorithmProperties.cryptoFunctions == ["sign"]
}

# The component contract applies to direct BOM construction and to each fixture
# modifier; missing required fields and malformed metadata cannot bypass it.
test_fixture_helpers_reject_invalid_component_shapes if {
	every component_patch in [
		{"type": 7}, {"name": null}, {"bom-ref": []}, {"cryptoProperties": []},
		{"evidence": null}, {"evidence": {"occurrences": {}}},
	] {
		invalid_component := object.union(valid_component, component_patch)
		not fixture_helpers.bom([invalid_component])
		not fixture_helpers.case("invalid component", [invalid_component], [])
		not fixture_helpers.with_ref(invalid_component, "new-reference")
		not fixture_helpers.with_oid(invalid_component, "1.2.3")
		not fixture_helpers.with_occurrence(invalid_component, "src/example.py", 1)
		not fixture_helpers.source_references(invalid_component)
	}
	every missing_field in ["type", "name", "bom-ref"] {
		not fixture_helpers.bom([object.remove(valid_component, {missing_field})])
	}
	protocol_component := object.union(valid_component, {"cryptoProperties": {"assetType": "protocol"}})
	not fixture_helpers.with_oid(protocol_component, "1.2.3")
}

# Occurrence comprehensions must reject a malformed entry rather than silently
# dropping it, especially when another source occurrence is valid.
test_malformed_occurrences_are_rejected_without_dropping_evidence if {
	every invalid_occurrence in [
		null, {}, {"location": 7}, {"location": "src/example.py", "line": "1"},
		{"location": "src/example.py", "line": 1.5},
		{"location": "src/example.py", "offset": -1},
		{"location": "src/example.py", "additionalContext": []},
	] {
		invalid_component := object.union(valid_component, {"evidence": {"occurrences": [
			{"location": "src/valid.py"}, invalid_occurrence,
		]}})
		not fixture_helpers.source_references(invalid_component)
		not fixture_helpers.bom([invalid_component])
	}
	component_with_location := object.union(valid_component, {"evidence": {"occurrences": [{"location": "src/example.py"}]}})
	fixture_helpers.source_references(component_with_location) == [{
		"location": "src/example.py", "line": -1, "offset": -1, "additionalContext": "",
	}]
	fixture_helpers.source_references(valid_component) == []
}

# Previously, count({}) and iteration over an empty object could satisfy the
# zero-findings check. Only actual arrays and sets of findings are accepted.
test_matches_rejects_non_collection_findings if {
	empty_case := fixture_helpers.case("empty", [], [])
	every invalid_findings in [{}, "", null, false, 0] {
		not fixture_helpers.matches(empty_case, invalid_findings)
	}
	fixture_helpers.matches(empty_case, [])
	fixture_helpers.matches(empty_case, set())
}

# Both supported collection types retain normal finding and subset matching.
test_matches_accepts_arrays_and_sets_of_typed_findings if {
	test_case := fixture_helpers.case("one finding", [valid_component], [{"ruleId": "helper-contract"}])
	fixture_helpers.matches(test_case, [valid_finding])
	fixture_helpers.matches(test_case, {valid_finding})
	not fixture_helpers.matches(test_case, [])
	not fixture_helpers.matches(test_case, [valid_finding, valid_finding])
}

# Test-case metadata and BOM fields must have their declared types even when
# the test has no findings and would otherwise perform no element checks.
test_matches_validates_the_test_case_shape if {
	empty_case := fixture_helpers.case("empty", [], [])
	every case_patch in [
		{"name": 7}, {"expected": {}}, {"expected": set()},
		{"evaluationTime": "2026-11-02"}, {"evaluationTime": 1.5},
		{"input": {"components": []}},
	] {
		invalid_case := object.union(object.remove(empty_case, object.keys(case_patch)), case_patch)
		not fixture_helpers.matches(invalid_case, [])
	}
	every bom_patch in [
		{"$schema": 7}, {"bomFormat": 7}, {"specVersion": 1.7},
		{"version": "1"}, {"version": 1.5}, {"components": {}},
	] {
		invalid_case := object.union(empty_case, {"input": object.union(empty_case.input, bom_patch)})
		not fixture_helpers.matches(invalid_case, [])
	}
}

# A matching expectation cannot legitimize an incorrectly typed finding.
test_matches_rejects_malformed_finding_fields if {
	every finding_patch in [
		{"ruleId": 7}, {"severity": null}, {"bomRef": []}, {"component": false},
		{"message": {}}, {"references": {}}, {"references": ["src/example.py"]},
		{"references": [{"location": "src/example.py", "line": "1", "offset": 0, "additionalContext": ""}]},
	] {
		invalid_finding := object.union(valid_finding, finding_patch)
		test_case := fixture_helpers.case("malformed finding", [valid_component], [invalid_finding])
		not fixture_helpers.matches(test_case, [invalid_finding])
	}
}

# Rego sets and non-string object keys cannot originate in a JSON CBOM. Nested
# occurrences of those values must also fail the deliberately permissive guard.
test_json_value_contract_rejects_non_json_values if {
	every json_value in [null, false, 7, "", [], {}, {"nested": [null, {"field": 7}]}] {
		test_types.is_json_value(json_value)
	}
	every invalid_json_value in [set(), {1, 2}, {7: "value"}, [{"nested": set()}], {"nested": [{7: "value"}]}] {
		not test_types.is_json_value(invalid_json_value)
		not getter_helpers.string_getter_results(invalid_json_value)
		not drbg_helpers.component(invalid_json_value, "DRBG", "")
	}
}

# Focused helper constructors still enforce their string parameters. Their
# explicitly documented arbitrary-JSON fields are exercised separately below.
test_focused_helpers_enforce_string_arguments if {
	every invalid_string in [null, true, 7, [], {}, set()] {
		not getter_helpers.ec_component(invalid_string, {})
		not oid_helpers.xof_component(invalid_string)
		not ec_helpers.component(invalid_string, {})
		not rsa_helpers.component(invalid_string, "pke", "RSA", "2048")
		not rsa_helpers.component("RSA", invalid_string, "RSA", "2048")
		not rsa_helpers.component("RSA", "pke", invalid_string, "2048")
		not encryption_helpers.component(invalid_string, "RSA", "")
		not encryption_helpers.component("RSA", invalid_string, "")
		not encryption_helpers.with_primitive(encryption_helpers.component("RSA", "RSA", ""), invalid_string)
		not signature_helpers.component(invalid_string, "ECDSA", "")
		not establishment_helpers.component(invalid_string, "DH", "")
		not establishment_helpers.component("DH", invalid_string, "")
		not drbg_helpers.component("Hash_DRBG", invalid_string, "")
	}
}

# Property maps have string keys; an array or scalar must not reach object.union.
test_focused_helpers_enforce_property_object_types if {
	every invalid_properties in [null, true, 7, "", [], set(), {7: "value"}] {
		not getter_helpers.ec_component("ECDH", invalid_properties)
		not ec_helpers.component("ECDH", invalid_properties)
		not encryption_helpers.with_properties(encryption_helpers.component("RSA", "", ""), invalid_properties)
		not signature_helpers.with_properties(signature_helpers.component("ECDSA", "", ""), invalid_properties)
		not establishment_helpers.with_properties(establishment_helpers.component("DH", "", ""), invalid_properties)
		not drbg_helpers.with_properties(drbg_helpers.component("Hash_DRBG", "", ""), invalid_properties)
	}
	every invalid_component in [null, [], {}, {"cryptoProperties": []}, {"cryptoProperties": {"algorithmProperties": []}}] {
		not encryption_helpers.with_properties(invalid_component, {})
		not signature_helpers.with_properties(invalid_component, {})
		not establishment_helpers.with_properties(invalid_component, {})
		not drbg_helpers.with_properties(invalid_component, {})
	}
}

# Raw helpers preserve malformed JSON fields so existing robustness tests still
# reach production getters and policies rather than failing at fixture setup.
test_focused_helpers_preserve_deliberately_malformed_json_fields if {
	every malformed_value in [null, true, 7, [], {}, ["RSA"]] {
		count(getter_helpers.string_getter_results(malformed_value)) == 13
		oid_helpers.with_oid(oid_helpers.xof_component("unknown"), malformed_value).cryptoProperties.oid == malformed_value
		ec_helpers.with_oid(ec_helpers.component("ECDH", {}), malformed_value).cryptoProperties.oid == malformed_value
		rsa_helpers.component("RSA", "pke", "RSA", malformed_value).cryptoProperties.algorithmProperties.parameterSetIdentifier == malformed_value
		encryption_helpers.component("RSA", "RSA", malformed_value).cryptoProperties.oid == malformed_value
		signature_helpers.component("ECDSA", malformed_value, malformed_value).cryptoProperties.algorithmProperties.algorithmFamily == malformed_value
		establishment_helpers.component("DH", "DH", malformed_value).cryptoProperties.oid == malformed_value
		drbg_helpers.component(malformed_value, "DRBG", malformed_value).name == malformed_value
		drbg_helpers.with_properties(drbg_helpers.component("Hash_DRBG", "", ""), {"primitive": malformed_value}).cryptoProperties.algorithmProperties.primitive == malformed_value
	}
}

# A policy returning an invalid collection or finding must not be converted into
# an empty set of rule IDs by a comprehension that drops malformed entries.
test_rule_id_helpers_reject_malformed_policy_results if {
	every invalid_findings in [[], {}, {7}, {{"ruleId": 7}}, {object.remove(valid_finding, {"ruleId"})}] {
		not establishment_helpers.rule_ids(establishment_helpers.component("DH", "", ""))
			with data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.findings as invalid_findings
		not drbg_helpers.rule_ids(drbg_helpers.component("Hash_DRBG", "", ""))
			with data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.findings as invalid_findings
	}
}

# Scalar getter adapters also enforce their array<string> result contract.
test_scalar_getter_adapter_rejects_non_string_results if {
	not getter_helpers.string_getter_results("Example")
		with data.cbom.eccg.getter_helpers.get_component_name_or_empty as 7
}
