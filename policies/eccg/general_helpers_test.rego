package cbom.eccg.general_helpers_test

# Shared identifier-normalization tests protect spelling compatibility without losing
# distinctions between different algorithm names.

import data.cbom.eccg.general_helpers.normalize_crypto_identifier

# Separator normalization must preserve distinctions such as DSA versus ECDSA while
# accepting supported spelling variations.
test_crypto_identifiers_normalize_without_collapsing_distinct_algorithms if {
	every raw_identifier, expected_normalized_identifier in {
		"DSA": "dsa",
		"ECDSA": "ecdsa",
		"MODP-3072": "modp3072",
		" FFDHE_2048 ": "ffdhe2048",
		"SHA-512/256": "sha512256",
		"KMAC (256)": "kmac256",
		"RSA-PKCS1-1.5": "rsapkcs115",
		"": "",
	} {
		normalize_crypto_identifier(raw_identifier) == expected_normalized_identifier
	}
}
