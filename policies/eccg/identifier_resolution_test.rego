package cbom.eccg.identifier_resolution_test

# Cross-section resolver regressions exercise OID, family, and name precedence using the
# resolvers currently exposed by the policies.

import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.helpers.get_asymmetric_encryption_scheme_or_empty as encryption_scheme
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.get_digital_signature_scheme_or_empty as signature_scheme
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers.get_key_establishment_scheme_or_empty as establishment_scheme
import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.oid_constants.NO_OID
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers.get_drbg_scheme_or_empty as drbg_scheme

# Exercise the resolvers present in the current policies. Older symmetric
# sections expose individual predicates; their recognition is covered by the
# corresponding section suites.
# Contradictory identifiers across encryption, signatures, and KEMs must resolve to the
# recognized OID’s scheme.
test_recognized_oid_precedes_registry_family_and_name if {
	encryption_component := test_helpers.with_oid(test_helpers.algorithm("ECIES", "pke", {"algorithmFamily": "ECIES"}), "1.2.840.113549.1.1.7")
	encryption_scheme(encryption_component) == "RSAES-OAEP"

	signature_component := test_helpers.with_oid(test_helpers.algorithm("Falcon", "signature", {"algorithmFamily": "SM2"}), "1.2.840.10045.4.3.2")
	signature_scheme(signature_component) == "ECDSA"

	key_establishment_component := test_helpers.with_oid(test_helpers.algorithm("X25519", "kem", {"algorithmFamily": "ECDH"}), "2.16.840.1.101.3.4.4.2")
	establishment_scheme(key_establishment_component) == "ML-KEM"
}

# Unrecognized OIDs leave recognized family identifiers authoritative over contradictory
# names.
test_unknown_oid_falls_back_to_registry_family if {
	encryption_component := test_helpers.with_oid(test_helpers.algorithm("ECIES", "pke", {"algorithmFamily": "RSAES-OAEP"}), "1.2.3.4.5")
	encryption_scheme(encryption_component) == "RSAES-OAEP"

	signature_component := test_helpers.with_oid(test_helpers.algorithm("Falcon", "signature", {"algorithmFamily": "ML-DSA"}), "1.2.3.4.5")
	signature_scheme(signature_component) == "ML-DSA"

	key_establishment_component := test_helpers.with_oid(test_helpers.algorithm("X25519", "kem", {"algorithmFamily": "ML-KEM"}), "1.2.3.4.5")
	establishment_scheme(key_establishment_component) == "ML-KEM"
}

# NO_OID is a placeholder rather than scheme evidence; family and name fallback must
# continue to work.
test_drbg_placeholder_allows_family_then_name_fallback if {
	every placeholder_or_unknown_oid in [NO_OID, trim_space(NO_OID), "1.2.3.4.5"] {
		component_identified_by_family := test_helpers.with_oid(test_helpers.algorithm("HMAC_DRBG", "drbg", {"algorithmFamily": "CTR_DRBG"}), placeholder_or_unknown_oid)
		drbg_scheme(component_identified_by_family) == "CTR_DRBG"

		component_identified_by_name := test_helpers.with_oid(test_helpers.algorithm("Hash_DRBG-SHA256", "drbg", {}), placeholder_or_unknown_oid)
		drbg_scheme(component_identified_by_name) == "Hash_DRBG"
	}
}
