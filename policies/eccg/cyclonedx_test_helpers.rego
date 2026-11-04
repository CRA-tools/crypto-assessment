package cbom.eccg.cyclonedx_test_helpers

import data.cbom.eccg.test_type_helpers as test_types

# Type notation in helper comments; guards below enforce these contracts:
#   array<T>: ordered collection; set<T>: unordered unique collection.
#   object<string, any>: object with string keys and arbitrary values.
#   A | B: either type; field?: optional field; ...: additional fields allowed.
#
# Shared object shapes:
#   Occurrence = {location: string, line?: number, offset?: number,
#                 additionalContext?: string}
#   SourceReference = {location: string, line: number, offset: number,
#                      additionalContext: string}
#   Component = {type: string, "bom-ref": string, name: string,
#                cryptoProperties?: object<string, any>,
#                evidence?: {occurrences?: array<Occurrence>}, ...}
#   AlgorithmComponent = Component with cryptoProperties containing
#       assetType: "algorithm", algorithmProperties: object<string, any>,
#       and optional oid: string.
#   CBOM = {"$schema": string, bomFormat: "CycloneDX", specVersion: "1.7",
#           version: number, components: array<Component>, ...}
#   Finding = {ruleId: string, severity: string, bomRef: string,
#              component: string, message: string,
#              references: array<SourceReference>, ...}
#   ExpectedFinding = object<string, any>: a subset of Finding fields to assert.
#   TestCase = {name: string, input: CBOM, expected: array<ExpectedFinding>,
#               evaluationTime: number (integer nanoseconds since Unix epoch)}

# Fixtures use CycloneDX 1.7, including its algorithm-family and curve enums.
# Evaluation time is mocked outside the BOM: policyEvaluationDate is not a
# CycloneDX root property. Malformed-input tests are kept separate.
# Type: number (integer nanoseconds since Unix epoch, UTC).
evaluation_time := time.parse_rfc3339_ns("2026-11-02T00:00:00Z")

# Construct the document passed directly to OPA as input. Component fields and enum
# values are checked separately by the exported-fixture schema validator.
# Args:
#   input_components: array<Component>.
# Returns: CBOM (object).
bom(input_components) := {
	"$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
	"bomFormat": "CycloneDX",
	"specVersion": "1.7",
	"version": 1,
	"components": input_components,
} if {
	is_array(input_components)
	every input_component in input_components {
		test_types.is_component(input_component)
	}
}

# Create an algorithm asset with CycloneDX nesting. algorithm_properties adds fields under
# algorithmProperties, including string parameterSetIdentifier values. Use with_ref when
# placing multiple assets in one BOM so their references are unique.
# Args:
#   algorithm_name: string.
#   primitive_type: string (CycloneDX primitive, such as "signature" or "drbg").
#   algorithm_properties: object<string, any>; fields such as algorithmFamily,
#       parameterSetIdentifier, and ellipticCurve are strings; cryptoFunctions
#       is array<string>. Supplied fields override the default primitive.
# Returns: AlgorithmComponent (object).
algorithm(algorithm_name, primitive_type, algorithm_properties) := {
	"type": "cryptographic-asset",
	"bom-ref": "algorithm-under-test",
	"name": algorithm_name,
	"cryptoProperties": {
		"assetType": "algorithm",
		"algorithmProperties": object.union({"primitive": primitive_type}, algorithm_properties),
	},
} if {
	is_string(algorithm_name)
	is_string(primitive_type)
	test_types.is_algorithm_properties(algorithm_properties)
}

# Attach the algorithm OID at cryptoProperties.oid while preserving its existing
# properties.
# Args:
#   input_component: AlgorithmComponent (requires a cryptoProperties object).
#   algorithm_oid: string.
# Returns: AlgorithmComponent (object) with the supplied OID.
with_oid(input_component, algorithm_oid) := object.union(input_component, {"cryptoProperties": object.union(input_component.cryptoProperties, {"oid": algorithm_oid})}) if {
	test_types.is_algorithm_component(input_component)
	is_string(algorithm_oid)
}

# Give an asset a distinct reference for dependency edges and finding attribution in
# multi-component fixtures.
# Args:
#   input_component: Component (object).
#   bom_reference: string.
# Returns: Component (object) with the supplied bom-ref.
with_ref(input_component, bom_reference) := object.union(input_component, {"bom-ref": bom_reference}) if {
	test_types.is_component(input_component)
	is_string(bom_reference)
}

# Attach one source occurrence in CycloneDX evidence.occurrences. This replaces existing
# evidence and is intended for fixtures that need a single location.
# Args:
#   input_component: Component (object).
#   source_file: string (source path).
#   line_number: number (positive integer, starting at 1).
# Returns: Component (object) with one Occurrence in evidence.occurrences.
with_occurrence(input_component, source_file, line_number) := object.union(input_component, {"evidence": {"occurrences": [{"location": source_file, "line": line_number}]}}) if {
	test_types.is_component(input_component)
	is_string(source_file)
	test_types.is_integer(line_number)
	line_number >= 1
}

# Bundle a readable test label, complete BOM, explicit expected findings, and clock
# value. The expected fields and evaluationTime are test metadata outside the CycloneDX
# input. Override evaluationTime on the case to test a legacy cutoff.
# Args:
#   case_name: string (test label).
#   input_components: array<Component>.
#   expected_findings: array<ExpectedFinding>; [] means no findings are expected.
# Returns: TestCase (object).
case(case_name, input_components, expected_findings) := {
	"name": case_name,
	"input": bom(input_components),
	"expected": expected_findings,
	"evaluationTime": evaluation_time,
} if {
	is_string(case_name)
	is_array(input_components)
	is_array(expected_findings)
	every expected_finding in expected_findings {
		test_types.is_string_keyed_object(expected_finding)
	}
	test_types.is_integer(evaluation_time)
}

# Compare an exact number of findings and their expected fields. Checking
# component identity and source references catches malformed build_finding
# calls that would otherwise pass a rule-ID-only assertion.
# Expected objects specify required fields using object.subset; extra metadata fields
# are allowed. The finding-count check still rejects extra findings, and each actual
# finding must refer to an input component.
# Args:
#   test_case: TestCase (object).
#   actual_findings: set<Finding> from a section, or array<Finding> from the
#       main assessment or a filtered selection of its findings.
# Returns: boolean true when all checks pass; undefined otherwise.
# Locals:
#   expected_finding: ExpectedFinding (object).
#   actual_finding: Finding (object).
#   input_component: Component (object).
matches(test_case, actual_findings) if {
	test_types.is_test_case(test_case)
	test_types.is_findings(actual_findings)
	count(actual_findings) == count(test_case.expected)
	every expected_finding in test_case.expected {
		some actual_finding in actual_findings
		object.subset(actual_finding, expected_finding)
	}
	every actual_finding in actual_findings {
		some input_component in test_case.input.components
		actual_finding.bomRef == input_component["bom-ref"]
		actual_finding.component == lower(trim_space(input_component.name))
		is_string(actual_finding.message)
		actual_finding.message != ""
		actual_finding.references == source_references(input_component)
	}
}

# Build the expected source-reference projection independently of production getters.
# Absent line/offset values use -1 and absent context uses an empty string; comparing
# this projection catches dropped or misattributed evidence.
# Args:
#   input_component: Component (object); evidence.occurrences is optional.
# Returns: array<SourceReference>; [] when no occurrences exist. line and offset
#   are integer numbers, with -1 representing an absent value.
# Locals:
#   source_occurrence: Occurrence (object).
source_references(input_component) := [
{
	"location": source_occurrence.location,
	"line": object.get(source_occurrence, "line", -1),
	"offset": object.get(source_occurrence, "offset", -1),
	"additionalContext": object.get(source_occurrence, "additionalContext", ""),
} |
	some source_occurrence in object.get(input_component, ["evidence", "occurrences"], [])
] if {
	test_types.is_component(input_component)
}

# Reusable negative-scope documents. They are valid CBOMs containing no relevant
# algorithm usage; an empty expected array applies to each section. The material example
# is a secret key, so the separate private/public-key rules also stay silent.
# Type: array<TestCase>.
scope_cases := [
	case("empty CycloneDX BOM", [], []),
	case("software library", [{"type": "library", "bom-ref": "library", "name": "ordinary-library"}], []),
	case(
		"unrelated protocol", [{
			"type": "cryptographic-asset", "bom-ref": "protocol", "name": "TLS",
			"cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.3"}},
		}],
		[],
	),
	case(
		"unrelated secret material", [{
			"type": "cryptographic-asset", "bom-ref": "material", "name": "application-secret",
			"cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "secret-key", "size": 256}},
		}],
		[],
	),
]
