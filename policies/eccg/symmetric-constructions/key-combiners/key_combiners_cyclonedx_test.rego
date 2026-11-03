package cbom.eccg.section_tests.key_combiners

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.symmetric_constructions.key_combiners.findings

# Potential key-combiner findings (ECCG-KC-001). Declared combiners, direct dependency
# graphs, and shared source files each provide different evidence. Expected method and
# heuristic fields preserve that distinction.
#
# Each test_helpers.case supplies a complete CycloneDX BOM and explicit expected findings. An empty
# expected array means no findings from this section. Other sections are assessed
# separately.
cases := [
	test_helpers.case("key-establishment name cannot change hash primitive", [test_helpers.algorithm("ECDH", "hash", {})], []),
	test_helpers.case("declared combiner", [test_helpers.algorithm("SP800-56C", "combiner", {})], [{"ruleId": "ECCG-KC-001", "severity": "warning", "bomRef": "algorithm-under-test", "method": "declared_combiner_primitive", "heuristic": true}]),
	# Resolve root dependencies by bom-ref. The candidate must depend on two distinct
	# key-establishment assets and a combining operation.
	object.union(test_helpers.case("hybrid direct dependencies", [{"type": "application", "bom-ref": "hybrid", "name": "hybrid"}, test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), test_helpers.with_ref(test_helpers.algorithm("ECDH", "key-agree", {}), "agreement"), test_helpers.with_ref(test_helpers.algorithm("HKDF", "kdf", {}), "kdf")], [{"ruleId": "ECCG-KC-001", "severity": "warning", "bomRef": "hybrid", "method": "dependencies", "heuristic": true}]), {"input": object.union(test_helpers.bom([{"type": "application", "bom-ref": "hybrid", "name": "hybrid"}, test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), test_helpers.with_ref(test_helpers.algorithm("ECDH", "key-agree", {}), "agreement"), test_helpers.with_ref(test_helpers.algorithm("HKDF", "kdf", {}), "kdf")]), {"dependencies": [{"ref": "hybrid", "dependsOn": ["kem", "agreement", "kdf"]}]})}),
	# Removing either the second establishment asset or the combining dependency must
	# suppress the dependency-based warning.
	object.union(test_helpers.case("one establishment dependency is insufficient", [{"type": "application", "bom-ref": "hybrid", "name": "hybrid"}, test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), test_helpers.with_ref(test_helpers.algorithm("HKDF", "kdf", {}), "kdf")], []), {"input": object.union(test_helpers.bom([{"type": "application", "bom-ref": "hybrid", "name": "hybrid"}, test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), test_helpers.with_ref(test_helpers.algorithm("HKDF", "kdf", {}), "kdf")]), {"dependencies": [{"ref": "hybrid", "dependsOn": ["kem", "kdf"]}]})}),
	object.union(test_helpers.case("no combining dependency", [{"type": "application", "bom-ref": "hybrid", "name": "hybrid"}, test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), test_helpers.with_ref(test_helpers.algorithm("ECDH", "key-agree", {}), "agreement")], []), {"input": object.union(test_helpers.bom([{"type": "application", "bom-ref": "hybrid", "name": "hybrid"}, test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), test_helpers.with_ref(test_helpers.algorithm("ECDH", "key-agree", {}), "agreement")]), {"dependencies": [{"ref": "hybrid", "dependsOn": ["kem", "agreement"]}]})}),
	# Same-file evidence triggers manual review; it cannot prove secret combination or the
	# order of cryptographic operations.
	test_helpers.case("same file occurrence heuristic", [test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), "src/hybrid.py", 10), test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("ECDH", "key-agree", {}), "agreement"), "src/hybrid.py", 20), test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("HKDF", "kdf", {}), "kdf"), "src/hybrid.py", 30)], [{"ruleId": "ECCG-KC-001", "severity": "warning", "bomRef": "kdf", "method": "occurrences_same_file", "sharedFile": "src/hybrid.py", "heuristic": true}]),
	test_helpers.case("separate files are insufficient", [test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), "src/hybrid.py", 10), test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("ECDH", "key-agree", {}), "agreement"), "src/other.py", 20), test_helpers.with_occurrence(test_helpers.with_ref(test_helpers.algorithm("HKDF", "kdf", {}), "kdf"), "src/hybrid.py", 30)], []),
	# The missing reference intentionally tests an incomplete dependency graph. It must not
	# count as a second resolved establishment component.
	object.union(test_helpers.case("unresolved dependency is insufficient", [{"type": "application", "bom-ref": "hybrid", "name": "hybrid"}, test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), test_helpers.with_ref(test_helpers.algorithm("HKDF", "kdf", {}), "kdf")], []), {"input": object.union(test_helpers.bom([{"type": "application", "bom-ref": "hybrid", "name": "hybrid"}, test_helpers.with_ref(test_helpers.algorithm("ML-KEM-768", "kem", {}), "kem"), test_helpers.with_ref(test_helpers.algorithm("HKDF", "kdf", {}), "kdf")]), {"dependencies": [{"ref": "hybrid", "dependsOn": ["kem", "missing", "kdf"]}]})}),
	test_helpers.case("source evidence is retained", [test_helpers.with_occurrence(test_helpers.algorithm("SP800-56C", "combiner", {}), "src/crypto.py", 42)], [{"ruleId": "ECCG-KC-001", "severity": "warning", "bomRef": "algorithm-under-test", "method": "declared_combiner_primitive", "heuristic": true}]),
]

# Evaluate each named CBOM against this section alone with a fixed clock. The expected
# finding count, fields, component identity, and source evidence must all match. OPA
# includes test_case.name in failures to identify the input.
test_cyclonedx_cases[test_case.name] if {
	some test_case in cases
	actual_findings := findings with input as test_case.input with time.now_ns as test_case.evaluationTime
	test_helpers.matches(test_case, actual_findings)
}

# Apply the shared empty-BOM, library, protocol, and secret-material cases. None should
# produce findings from this section.
test_cyclonedx_scope[test_case.name] if {
	some test_case in test_helpers.scope_cases
	actual_findings := findings with input as test_case.input with time.now_ns as test_case.evaluationTime
	test_helpers.matches(test_case, actual_findings)
}

# Run the full assessment and select this section’s findings. Other sections can
# legitimately assess the same component; this selection verifies that aggregation
# preserves these findings and their UI location metadata.
test_cyclonedx_main_findings[test_case.name] if {
	some test_case in array.concat(cases, test_helpers.scope_cases)
	all_findings := data.cbom.eccg.findings with input as test_case.input with time.now_ns as test_case.evaluationTime
	section_findings := [finding |
		some finding in all_findings
		finding.section == "Symmetric Constructions"
		finding.subsection == "Key Combiners"
	]
	test_helpers.matches(test_case, section_findings)
	every finding in section_findings {
		finding.policyPath == "Symmetric Constructions / Key Combiners"
	}
}
