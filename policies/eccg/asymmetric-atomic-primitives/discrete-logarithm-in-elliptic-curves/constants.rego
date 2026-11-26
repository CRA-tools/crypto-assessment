package cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_elliptic_curves.constants

# Curve identifiers. Policy selection and normalization belong in helpers.rego.
BRAINPOOL_P256R1_CURVE_NAMES := {
	"BrainpoolP256r1",
	"brainpool/brainpoolP256r1",
}

BRAINPOOL_P384R1_CURVE_NAMES := {
	"BrainpoolP384r1",
	"brainpool/brainpoolP384r1",
}

BRAINPOOL_P512R1_CURVE_NAMES := {
	"BrainpoolP512r1",
	"brainpool/brainpoolP512r1",
}

NIST_P256_CURVE_NAMES := {
	"NIST P-256", "nist/P-256", "P-256",
	"secg/secp256r1", "secp256r1",
	"x962/prime256v1", "prime256v1",
}

NIST_P384_CURVE_NAMES := {
	"NIST P-384", "nist/P-384", "P-384", "secg/secp384r1", "secp384r1",
}

NIST_P521_CURVE_NAMES := {
	"NIST P-521", "nist/P-521", "P-521", "secg/secp521r1", "secp521r1",
}

FRP256V1_CURVE_NAMES := {"FRP256v1", "anssi/FRP256v1"}

# Scanner identifiers for the RFC7748 curves and their associated operations.
# The Edwards forms used by EdDSA are defined in RFC8032.
CURVE25519_CURVE_NAMES := {"Curve25519", "other/Curve25519", "X25519"}

CURVE448_CURVE_NAMES := {"Curve448", "other/Curve448", "X448"}

ED25519_CURVE_NAMES := {"Edwards25519", "Ed25519", "other/Ed25519"}

ED448_CURVE_NAMES := {"Edwards448", "Ed448", "other/Ed448"}

# Algorithm identifiers describe EC-DLOG usage independently of compliance.
EC_DLOG_PRIMITIVE_FAMILIES := {
	"EC",
	"ECC",
	"EC-DLOG",
	"ECDH",
	"ECDHE",
	"ECMQV",
	"X25519",
	"X448",
	"ECDSA",
	"EdDSA",
	"Ed25519",
	"Ed448",
	"ECIES",
	"EC-ElGamal",
}

EC_DLOG_PRIMITIVE_NAMES := {
	"EC", "ECC", "EC-DLOG",
	"ECDH", "ECDHE", "ECMQV", "X25519", "X448",
	"ECDSA", "EdDSA", "Ed25519", "Ed448", "ECIES", "EC-ElGamal",
	"id-ecPublicKey", "id-ecDH", "id-ecMQV",
	"SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA",
	"SHA384withECDSA", "SHA512withECDSA",
	"ECDSAwithSHA1", "ECDSAwithSHA224", "ECDSAwithSHA256",
	"ECDSAwithSHA384", "ECDSAwithSHA512",
}

# These are algorithm OIDs, not named-curve OIDs.
# Sources:
# - https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1
# - https://www.rfc-editor.org/rfc/rfc3279.html#section-2.2.3
# - https://www.rfc-editor.org/rfc/rfc5758.html#section-3.2
# - https://www.rfc-editor.org/rfc/rfc8410.html#section-3
EC_DLOG_PRIMITIVE_OIDS := {
	"id-ecPublicKey": "1.2.840.10045.2.1",
	"id-ecDH": "1.3.132.1.12",
	"id-ecMQV": "1.3.132.1.13",
	"ecdsa-with-SHA1": "1.2.840.10045.4.1",
	"ecdsa-with-SHA224": "1.2.840.10045.4.3.1",
	"ecdsa-with-SHA256": "1.2.840.10045.4.3.2",
	"ecdsa-with-SHA384": "1.2.840.10045.4.3.3",
	"ecdsa-with-SHA512": "1.2.840.10045.4.3.4",
	"X25519": "1.3.101.110",
	"X448": "1.3.101.111",
	"Ed25519": "1.3.101.112",
	"Ed448": "1.3.101.113",
}
