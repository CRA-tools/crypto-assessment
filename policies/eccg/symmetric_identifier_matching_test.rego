package cbom.eccg.symmetric_identifier_matching_test

import data.cbom.eccg.cyclonedx_test_helpers as test_helpers
import data.cbom.eccg.classifying_helpers.is_key_establishment_primitive
import data.cbom.eccg.general_helpers.matches_crypto_identifier
import data.cbom.eccg.symmetric_atomic_primitives.hashes.helpers as hash_helpers
import data.cbom.eccg.symmetric_atomic_primitives.xofs.helpers as xof_helpers
import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants as xof_constants
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers as block_helpers
import data.cbom.eccg.symmetric_constructions.macs.helpers as mac_helpers
import data.cbom.eccg.symmetric_constructions.key_derivation.helpers as kdf_helpers
import data.cbom.eccg.symmetric_constructions.key_derivation.findings as kdf_findings
import data.cbom.eccg.symmetric_constructions.key_derivation.constants as kdf_constants
import data.cbom.eccg.symmetric_constructions.key_protection.helpers as protection_helpers
import data.cbom.eccg.symmetric_constructions.key_protection.constants as protection_constants
import data.cbom.eccg.symmetric_constructions.password_protection.helpers as password_helpers
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers as encryption_helpers

test_complete_alias_matching if {
	matches_crypto_identifier(" SHA_512/256 ", {"SHA-512/256"})
	not matches_crypto_identifier("SHA-512/224", {"SHA-512"})
	not matches_crypto_identifier("custom-SHA-512", {"SHA-512"})
	not matches_crypto_identifier("SHA-512-custom", {"SHA-512"})
}

test_sha512_truncations_are_distinct[hash_name] if {
	some hash_name in ["SHA-512/256", "sha_512_256", "SHA512(256)"]
	hash_component := test_helpers.algorithm(hash_name, "hash", {})
	hash_helpers.is_sha512_256(hash_component)
	not hash_helpers.is_sha512(hash_component)
}

test_unagreed_hash_names[hash_name] if {
	some hash_name in ["SHA-224", "SHA-512/224", "sha_512_224", "SHA512(224)", "SHA-256/128", "SHA3-512/224", "custom-SHA-256", "SHA-384-custom"]
	hash_component := test_helpers.algorithm(hash_name, "hash", {})
	not hash_helpers.is_agreed_hash_component(hash_component)
}

test_cshake_does_not_match_shake[output_suffix] if {
	some output_suffix in ["", "-256", "-512"]
	cshake128_component := test_helpers.algorithm(concat("", ["cSHAKE128", output_suffix]), "xof", {})
	xof_helpers.is_cshake128(cshake128_component)
	not xof_helpers.is_shake128(cshake128_component)
	cshake256_component := test_helpers.algorithm(concat("", ["cSHAKE256", output_suffix]), "xof", {})
	xof_helpers.is_cshake256(cshake256_component)
	not xof_helpers.is_shake256(cshake256_component)
}

test_xof_oid_takes_precedence_over_name if {
	xof_component := test_helpers.with_oid(
		test_helpers.algorithm("cSHAKE128-256", "xof", {"algorithmFamily": "SHA-3"}),
		xof_constants.SHAKE_XOF_ALGORITHM_OIDS["SHAKE256"],
	)
	xof_helpers.is_shake256(xof_component)
	not xof_helpers.is_cshake128(xof_component)
}

test_xof_unknown_oid_falls_back_to_name if {
	xof_component := test_helpers.with_oid(
		test_helpers.algorithm("cSHAKE128-256", "xof", {"algorithmFamily": "SHA-3"}),
		"1.2.3.4.5",
	)
	xof_helpers.is_cshake128(xof_component)
	not xof_helpers.is_shake128(xof_component)
}

test_unagreed_xof_names[xof_name] if {
	some xof_name in ["custom-SHAKE128", "SHAKE256-custom", "cSHAKE2560"]
	xof_component := test_helpers.algorithm(xof_name, "xof", {})
	not xof_helpers.is_agreed_xof_component(xof_component)
}

test_aes_family_detection_independent_of_mode[cipher_name] if {
	some cipher_name in ["AES", "AES-256", "AES-160", "AES-128-CBC", "AES-256-GCM-SIV", "AES/CFB8", "AES-ECB", "AES-OCB", "AESGCM", "AES-custom", "AES-256-GCM-128-96"]
	cipher_component := test_helpers.algorithm(cipher_name, "block-cipher", {})
	block_helpers.is_aes_component(cipher_component)
}

test_unrelated_cipher_names[cipher_name] if {
	some cipher_name in ["Camellia", "Blowfish"]
	cipher_component := test_helpers.algorithm(cipher_name, "block-cipher", {})
	not block_helpers.is_aes_component(cipher_component)
	not block_helpers.is_3des_component(cipher_component)
}

test_3des_family_detection_independent_of_mode[cipher_name] if {
	some cipher_name in ["3DES-168-CBC", "TripleDES-custom", "TDEA-ECB", "DES-EDE3-CBC", "custom-3DES", "custom-TripleDES"]
	cipher_component := test_helpers.algorithm(cipher_name, "block-cipher", {})
	block_helpers.is_3des_component(cipher_component)
}

test_ecb_is_detected_as_aes_and_rejected[cipher_name] if {
	some cipher_name in ["AES-ECB", "AES-256-ECB", "AES256ECB"]
	cipher_component := test_helpers.algorithm(cipher_name, "block-cipher", {"parameterSetIdentifier": "256"})
	block_helpers.is_aes_component(cipher_component)
	not encryption_helpers.is_agreed_symmetric_encryption_scheme(cipher_component)
	input_cbom := test_helpers.bom([cipher_component])
	actual_findings := data.cbom.eccg.findings with input as input_cbom with time.now_ns as test_helpers.evaluation_time
	some finding in actual_findings
	finding.ruleId == "ECCG-SYM-ENC-001"
	finding.severity == "critical"
}

test_cbc_mac_does_not_match_cmac if {
	cbc_mac_component := test_helpers.algorithm("AES-CBC-MAC", "mac", {})
	mac_helpers.is_cbcmac_scheme(cbc_mac_component)
	not mac_helpers.is_cmac_scheme(cbc_mac_component)
}

test_unagreed_mac_names[mac_name] if {
	some mac_name in ["KMAC512", "custom-GMAC", "CMAC-custom", "CBC-MAC-custom"]
	mac_component := test_helpers.algorithm(mac_name, "mac", {})
	not mac_helpers.is_agreed_mac_scheme(mac_component)
}

test_hmac_construction_accepts_hash_variants_and_tag_lengths[mac_name] if {
	some mac_name in [
		"HMAC", "HMAC-MD5", "HMAC-RIPEMD160", "HMAC-SHA224", "HMAC-SHA3-224",
		"HMAC-SHA512/224", "HMAC-SHA512-224", "HMAC-SHA512_224", "provider-HMAC-SHA512-224",
		"HMAC-SHA512-224-128", "HMAC-SHA224-128", "HMAC-SHA3-224-128", "HMAC-SHA256-custom",
		"HMAC-SHA512-128", "HMAC-SHA512/256-128", "HMAC-SHA512-256-128", "HMAC-SHA256-224",
		"HMAC-SHA3-256-224", "provider-HMAC-SHA512/256-224", "HMAC-SHA1-96",
	]
	mac_component := test_helpers.algorithm(mac_name, "mac", {})
	mac_helpers.is_hmac_scheme(mac_component)
	mac_helpers.is_agreed_hmac_scheme(mac_component) with time.now_ns as test_helpers.evaluation_time
}

test_hmac_sha1_requires_complete_hash_name[mac_name] if {
	some mac_name in ["HMAC-SHA10", "HMAC-SHA128", "HMAC-SHA1-custom"]
	mac_component := test_helpers.algorithm(mac_name, "mac", {"algorithmFamily": "HMAC"})
	not mac_helpers.is_hmac_sha1_scheme(mac_component)
	mac_helpers.is_hmac_scheme(mac_component)
}

test_kmac_family_recognition_does_not_approve_unsupported_variants[mac_name] if {
	some mac_name in ["KMAC512", "KMACXOF128", "KMACXOF256", "KMAC128-custom"]
	mac_component := test_helpers.algorithm(mac_name, "mac", {"algorithmFamily": "SHA-3"})
	mac_helpers.is_kmac_scheme(mac_component)
	not mac_helpers.is_agreed_mac_scheme(mac_component)
}

test_ansi_family_recognition_does_not_approve_unsupported_variants[kdf_name] if {
	some kdf_name in ["ANSI-X9.42-KDF", "X942KDF", "ANSI-custom"]
	kdf_component := test_helpers.algorithm(kdf_name, "kdf", {"algorithmFamily": "ANSI-KDF"})
	kdf_helpers.is_ansi_x963_kdf(kdf_component)
	not kdf_helpers.is_agreed_kdf_scheme(kdf_component)
}

# These registry families are absent from the CycloneDX 1.7 schema enum.
# Keep compatibility checks outside the schema-valid fixture export.
test_kdf_family_compatibility[test_case.name] if {
	some test_case in [
		test_helpers.case("X963KDF SHA224 with ANSI family", [test_helpers.algorithm("X963KDF-SHA224", "kdf", {"algorithmFamily": "ANSI-KDF"})], []),
		test_helpers.case("ANSI KDF registry family with opaque name", [test_helpers.algorithm("opaque", "kdf", {"algorithmFamily": "ANSI-KDF"})], []),
		test_helpers.case("unknown OID falls back to ANSI KDF family", [test_helpers.with_oid(test_helpers.algorithm("opaque", "kdf", {"algorithmFamily": "ANSI-KDF"}), "1.2.3.4")], []),
		test_helpers.case("ANSI family with agreed X9.63 name", [test_helpers.algorithm("ANSI-X9.63-KDF", "kdf", {"algorithmFamily": "ANSI-KDF"})], []),
		test_helpers.case("ANSI family cannot approve X9.42 as X9.63", [test_helpers.algorithm("ANSI-KDF-X9.42", "kdf", {"algorithmFamily": "ANSI-KDF"})], [{"ruleId": "ECCG-KDF-001", "severity": "medium", "bomRef": "algorithm-under-test"}]),
		test_helpers.case("SP800-56C registry family", [test_helpers.algorithm("opaque", "kdf", {"algorithmFamily": "SP800-56C"})], []),
	]
	actual_findings := kdf_findings with input as test_case.input with time.now_ns as test_case.evaluationTime
	test_helpers.matches(test_case, actual_findings)
}

test_declared_kdf_aliases[kdf_name] if {
	some kdf_name in kdf_constants.NIST_SP800_56_KDF_NAMES | kdf_constants.ANSI_X963_KDF_NAMES | kdf_constants.PBKDF2_KDF_NAMES | kdf_constants.HKDF_KDF_NAMES
	kdf_component := test_helpers.algorithm(kdf_name, "kdf", {})
	kdf_helpers.is_agreed_kdf_scheme(kdf_component)
}

test_unagreed_kdf_names[kdf_name] if {
	some kdf_name in ["ANSI-X9.42-KDF", "ANSI-custom", "SP800-56D", "custom-HKDF", "HKDF2", "PBKDF20"]
	kdf_component := test_helpers.algorithm(kdf_name, "kdf", {})
	not kdf_helpers.is_agreed_kdf_scheme(kdf_component)
}

test_declared_key_protection_aliases[protection_name] if {
	some protection_name in protection_constants.SIV_KEY_PROTECTION_SCHEME_NAMES | protection_constants.AES_KEYWRAP_KEY_PROTECTION_SCHEME_NAMES
	protection_component := test_helpers.algorithm(protection_name, "key-wrap", {})
	protection_helpers.is_agreed_key_protection_scheme(protection_component)
}

test_unagreed_key_protection_names[protection_name] if {
	some protection_name in ["custom-SIV", "AES-SIV-custom", "custom-KW", "RSA-KeyWrap", "AES-KWP-custom"]
	protection_component := test_helpers.algorithm(protection_name, "key-wrap", {})
	not protection_helpers.is_agreed_key_protection_scheme(protection_component)
}

test_argon2_requires_id_variant[password_hash_name] if {
	some password_hash_name in ["Argon2", "Argon2i", "Argon2d", "Argon2id-custom", "custom-Argon2id"]
	password_hash_component := test_helpers.algorithm(password_hash_name, "kdf", {"algorithmFamily": "Argon2"})
	not password_helpers.is_argon2id_scheme(password_hash_component)
}

test_argon2id_names[password_hash_name] if {
	some password_hash_name in ["Argon2id", "Argon2-id", "Argon2id-v19", "Argon2id-2097152-1-4"]
	password_hash_component := test_helpers.algorithm(password_hash_name, "kdf", {"algorithmFamily": "Argon2"})
	password_helpers.is_argon2id_scheme(password_hash_component)
}

test_cbc_cs_and_essiv_are_not_plain_cbc if {
	cbc_cs_component := test_helpers.algorithm("AES-CBC-CS3", "block-cipher", {})
	encryption_helpers.is_cbc_cs_scheme(cbc_cs_component)
	not encryption_helpers.is_cbc_scheme(cbc_cs_component)
	essiv_component := test_helpers.algorithm("AES-CBC-ESSIV", "block-cipher", {})
	encryption_helpers.is_cbc_essiv_scheme(essiv_component)
	not encryption_helpers.is_cbc_scheme(essiv_component)
}

test_gcm_siv_is_not_gcm if {
	gcm_siv_component := test_helpers.algorithm("AES-GCM-SIV", "ae", {"algorithmFamily": "AES", "mode": "gcm"})
	protection_helpers.is_gcm_siv_scheme(gcm_siv_component)
	not protection_helpers.is_siv_scheme(gcm_siv_component)
	not protection_helpers.is_agreed_key_protection_scheme(gcm_siv_component)
	not encryption_helpers.is_gcm_scheme(gcm_siv_component)
}

test_kdf_hash_metadata_preserves_variants[kdf_name] if {
	some kdf_name, expected_hash in {
		"HKDF-SHA512": "SHA-512",
		"HKDF-SHA512/224": "SHA-512/224",
		"HKDF-SHA512/256": "SHA-512/256",
		"HKDF-SHA512/999": "",
		"PBKDF2-HMAC-SHA256-600000-32": "SHA-256",
		"PBKDF2-HMAC-SHA512/224-600000-32": "SHA-512/224",
	}
	kdf_component := test_helpers.algorithm(kdf_name, "kdf", {})
	kdf_helpers.get_kdf_underlying_hash_name_or_empty(kdf_component) == expected_hash with input as {}
}

test_mode_cannot_change_primitive_classification if {
	cipher_component := test_helpers.algorithm("AES", "block-cipher", {"mode": "ecdh"})
	not is_key_establishment_primitive(cipher_component)
}

test_unagreed_encryption_mode_names[encryption_name] if {
	some encryption_name in ["custom-CTR", "AES-CBC-custom", "AES-CBC-CS4", "AES-CFB8-custom", "AES-XTS-custom", "AES-CBC-ESSIV-custom"]
	encryption_component := test_helpers.algorithm(encryption_name, "block-cipher", {})
	not encryption_helpers.is_agreed_symmetric_encryption_scheme(encryption_component)
	not encryption_helpers.is_agreed_disk_encryption_scheme(encryption_component)
}

test_unagreed_ae_names[encryption_name] if {
	some encryption_name in ["custom-GCM", "AES-GCM-custom", "custom-CCM", "AES-CCM-custom", "AES-EAX-custom"]
	every mode_name in ["gcm", "ccm"] {
		encryption_component := test_helpers.algorithm(encryption_name, "ae", {"mode": mode_name})
		not encryption_helpers.is_agreed_authenticated_encryption_scheme(encryption_component)
	}
}
