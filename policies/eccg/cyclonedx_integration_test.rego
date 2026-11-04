package cbom.eccg.cyclonedx_integration_test

# Integration checks bind the section suites to the main assessment. The fixture export
# reuses the exact BOMs evaluated by the section tests for independent JSON Schema
# validation.

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers

# Keep the section inventory explicit, so adding/removing a policy source
# requires updating its test coverage.
# Type: array<SectionSuite>, where SectionSuite is an object with section: string,
#   subsection: string, active: boolean, and cases: array<TestCase>.
#   TestCase, CBOM, and ExpectedFinding shapes are in cyclonedx_test_helpers.rego.
section_suites := [
	{"section": "Symmetric Atomic Primitives", "subsection": "Block Ciphers", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.block_ciphers.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Atomic Primitives", "subsection": "Hash Primitives", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.hashes.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Atomic Primitives", "subsection": "XOFs", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.xofs.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Constructions", "subsection": "AES Modes", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.aes_modes.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Constructions", "subsection": "Authenticated Encryption", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.authenticated_encryption.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Constructions", "subsection": "Disk Encryption", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.disk_encryption.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Constructions", "subsection": "Mac", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.macs.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Constructions", "subsection": "Key Derivation", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.key_derivation.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Constructions", "subsection": "Key Protection", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.key_protection.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Constructions", "subsection": "Password Hashing", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.password_protection.cases, test_helpers.scope_cases)},
	{"section": "Symmetric Constructions", "subsection": "Key Combiners", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.key_combiners.cases, test_helpers.scope_cases)},
	{"section": "Asymmetric Atomic Primitives", "subsection": "FF DLOG", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.ff_dlog.cases, test_helpers.scope_cases)},
	{"section": "Asymmetric Atomic Primitives", "subsection": "RSA Integer Factorization", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.rsa.cases, test_helpers.scope_cases)},
	{"section": "Asymmetric Atomic Primitives", "subsection": "EC DLOG", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.ec_dlog.cases, test_helpers.scope_cases)},
	{"section": "Asymmetric Constructions", "subsection": "Asymmetric Encryption Schemes", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.asymmetric_encryption.cases, test_helpers.scope_cases)},
	{"section": "Asymmetric Constructions", "subsection": "Digital Signature Schemes", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.digital_signatures.cases, test_helpers.scope_cases)},
	{"section": "Asymmetric Constructions", "subsection": "Key Establishment and Key Encapsulation Schemes", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.key_establishment.cases, test_helpers.scope_cases)},
	{"section": "Random Number Generation", "subsection": "Deterministic Random Bit Generator", "active": true, "cases": array.concat(data.cbom.eccg.section_tests.drbg.cases, test_helpers.scope_cases)},
	{"section": "General", "subsection": "Key Material", "active": false, "cases": array.concat(data.cbom.eccg.section_tests.key_material.cases, test_helpers.scope_cases)},
]

# Export with opa eval --format raw for official CycloneDX schema validation.
# Only each entry’s bom member is a CycloneDX document. suite, case, and expected are
# test metadata retained for readable validation errors and rule-ID coverage checks.
# Type: array<object {suite: string, case: string, bom: CBOM,
#                     expected: array<ExpectedFinding>}>.
# Locals:
#   section_suite: SectionSuite (object).
#   test_case: TestCase (object).
fixture_documents := [
{"suite": section_suite.subsection, "case": test_case.name, "bom": test_case.input, "expected": test_case.expected} |
	some section_suite in section_suites
	some test_case in section_suite.cases
]

# Inventory rule IDs with an explicitly expected finding. This supports coverage audits;
# the schema-validation script also compares these expectations with IDs declared in
# production policies.
# Type: set<string> of ECCG rule identifiers.
# Locals:
#   section_suite: SectionSuite (object).
#   test_case: TestCase (object).
#   expected_finding: ExpectedFinding (object with a string ruleId).
covered_rule_ids := {expected_finding.ruleId |
	some section_suite in section_suites
	some test_case in section_suite.cases
	some expected_finding in test_case.expected
}

# Compare the explicit suite inventory with main.rego so adding or removing an active
# policy source requires updating its test coverage.
test_every_active_section_has_a_suite if {
	active_policy_sections := {[policy_source.section, policy_source.subsection] | some policy_source in data.cbom.eccg.policy_sources}
	tested_sections := {[section_suite.section, section_suite.subsection] | some section_suite in section_suites; section_suite.active}
	active_policy_sections == tested_sections
	count(active_policy_sections) == 18
}

# Two hash assets with different expected severities must retain their own bom-ref
# values and appear exactly once in the combined result.
test_main_returns_both_components_without_duplicates if {
	md5_component := test_helpers.with_ref(test_helpers.algorithm("MD5", "hash", {}), "md5")
	sha256_component := test_helpers.with_ref(test_helpers.algorithm("SHA-256", "hash", {"parameterSetIdentifier": "256"}), "sha256")
	test_case := test_helpers.case("mixed BOM", [md5_component, sha256_component], [
		{"ruleId": "ECCG-HASH-001", "severity": "critical", "bomRef": "md5"},
		{"ruleId": "ECCG-HASH-002", "severity": "medium", "bomRef": "sha256"},
	])
	actual_findings := data.cbom.eccg.findings with input as test_case.input with time.now_ns as test_case.evaluationTime
	test_helpers.matches(test_case, actual_findings)
}

# Pin the Rego endpoint’s current zero-findings contract: both critical findings and
# advisory warnings make compliant false.
test_main_compliance[test_case.name] if {
	some test_case in [
		{"name": "empty BOM", "components": [], "expected": true},
		{"name": "agreed hash", "components": [test_helpers.algorithm("SHA-384", "hash", {"parameterSetIdentifier": "384"})], "expected": true},
		{"name": "critical finding", "components": [test_helpers.algorithm("MD5", "hash", {})], "expected": false},
		# The Rego endpoint currently requires zero findings, including warnings.
		{"name": "advisory finding", "components": [test_helpers.algorithm("Hash_DRBG", "drbg", {})], "expected": false},
	]
	is_compliant := data.cbom.eccg.compliant with input as test_helpers.bom(test_case.components) with time.now_ns as test_helpers.evaluation_time
	is_compliant == test_case.expected
}

# Private-key material has direct policy coverage but must remain absent from the
# combined assessment while that section is disabled.
test_key_material_policy_is_not_aggregated if {
	some section_suite in section_suites
	not section_suite.active
	some test_case in section_suite.cases
	test_case.name == "private key review"
	actual_findings := data.cbom.eccg.findings with input as test_case.input with time.now_ns as test_helpers.evaluation_time
	count(actual_findings) == 0
}
