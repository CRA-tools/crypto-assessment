package cbom.eccg.random_number_generation.deterministic_random_bit_generator

import data.cbom.eccg.classifying_helpers.is_drbg_primitive
import data.cbom.eccg.general_helpers.build_finding
import data.cbom.eccg.getter_helpers.get_note

import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.MIN_SEED_ENTROPY_BITS
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.QUANTUM_MIN_CTR_KEY_BITS
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.QUANTUM_MIN_SEED_ENTROPY_BITS
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.AGREED_DRBG_SCHEMES
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.drbg_metadata
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.get_drbg_scheme_or_empty
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.is_agreed_drbg_scheme

default compliant := false

compliant if count(findings) == 0

SECTION := "Random-Number-Generation"
SUBSECTION := "Deterministic-Random-Bit-Generator"

# ECCG-DRBG-001: All three R entries in Section 7.2 are agreed.
findings contains finding if {
	some component in input.components
	is_drbg_primitive(component)
	not is_agreed_drbg_scheme(component)
	metadata := drbg_metadata(component)

	finding := build_finding(
		"ECCG-DRBG-001",
		"critical",
		sprintf("Deterministic random bit generator '%s' is not in the ECCG agreed scheme list. The agreed DRBG schemes are: %s.", [metadata.schemeIdentifier, concat(", ", sort(AGREED_DRBG_SCHEMES))]),
		component,
		metadata,
	)
}

# These are implementation obligations, not inferred failures: the algorithm
# inventory does not prove seed min-entropy, reseeding, application security
# requirements, backtracking resistance, or the underlying cipher's key size.
findings contains finding if {
	some component in input.components
	is_agreed_drbg_scheme(component)
	metadata := drbg_metadata(component)

	finding := build_finding(
		"ECCG-DRBG-002",
		"warning",
		sprintf("%s detected. Verify that initial seeding and reseeding use a random source satisfying the generator specification's minimum entropy requirements, and that the seed has at least %d bits of min-entropy. Seed length alone does not establish min-entropy.", [metadata.schemeIdentifier, MIN_SEED_ENTROPY_BITS]),
		component,
		object.union(metadata, {"notes": get_note(SECTION, SUBSECTION, "71-DRG-Seeding")}),
	)
}

findings contains finding if {
	some component in input.components
	is_agreed_drbg_scheme(component)
	metadata := drbg_metadata(component)

	finding := build_finding(
		"ECCG-DRBG-003",
		"warning",
		sprintf("%s detected. Where resistance to quantum attacks is required, verify that the seed has at least %d bits of min-entropy.", [metadata.schemeIdentifier, QUANTUM_MIN_SEED_ENTROPY_BITS]),
		component,
		object.union(metadata, {"notes": get_note(SECTION, SUBSECTION, "72-Quantum-Threat")}),
	)
}

findings contains finding if {
	some component in input.components
	is_agreed_drbg_scheme(component)
	metadata := drbg_metadata(component)

	finding := build_finding(
		"ECCG-DRBG-004",
		"warning",
		sprintf("%s detected. Where perfect forward secrecy is required, verify backtracking resistance: disclosure of the current generator state must not enable reconstruction of past outputs used for ephemeral keys.", [metadata.schemeIdentifier]),
		component,
		object.union(metadata, {"notes": get_note(SECTION, SUBSECTION, "73-BacktrackingResistance")}),
	)
}

findings contains finding if {
	some component in input.components
	is_agreed_drbg_scheme(component)
	get_drbg_scheme_or_empty(component) == "CTR_DRBG"

	finding := build_finding(
		"ECCG-DRBG-005",
		"warning",
		sprintf("CTR_DRBG detected. Where resistance to quantum attacks is required, use an underlying block cipher with a key size of at least %d bits. Verify the cipher key size independently of the seed length and requested security strength.", [QUANTUM_MIN_CTR_KEY_BITS]),
		component,
		object.union(drbg_metadata(component), {"notes": get_note(SECTION, SUBSECTION, "74-QuantumThreat")}),
	)
}
