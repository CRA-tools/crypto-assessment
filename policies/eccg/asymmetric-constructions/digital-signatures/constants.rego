package cbom.eccg.asymmetric_constructions.digital_signatures.constants

# Only signature identifiers belong in this map. Generic rsaEncryption and
# id-ecPublicKey do not identify signature padding or signature use.
# Schemes without a verified OID remain recognizable by family and name.
DIGITAL_SIGNATURE_OIDS := {
	# RFC 8017, Appendix A.2.3/A.2.4.
	# https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.2.3
	"1.2.840.113549.1.1.10": "RSASSA-PSS",
	"1.2.840.113549.1.1.2": "RSASSA-PKCS1-v1_5",
	"1.2.840.113549.1.1.4": "RSASSA-PKCS1-v1_5",
	"1.2.840.113549.1.1.5": "RSASSA-PKCS1-v1_5",
	"1.2.840.113549.1.1.11": "RSASSA-PKCS1-v1_5",
	"1.2.840.113549.1.1.12": "RSASSA-PKCS1-v1_5",
	"1.2.840.113549.1.1.13": "RSASSA-PKCS1-v1_5",
	"1.2.840.113549.1.1.14": "RSASSA-PKCS1-v1_5",
	"1.2.840.113549.1.1.15": "RSASSA-PKCS1-v1_5",
	"1.2.840.113549.1.1.16": "RSASSA-PKCS1-v1_5",

	# https://www.rfc-editor.org/rfc/rfc3279.html#section-2.2
	# https://www.rfc-editor.org/rfc/rfc5758.html#section-3.2
	"1.2.840.10040.4.3": "DSA",
	"1.2.840.10045.4.1": "ECDSA",
	"1.2.840.10045.4.3.1": "ECDSA",
	"1.2.840.10045.4.3.2": "ECDSA",
	"1.2.840.10045.4.3.3": "ECDSA",
	"1.2.840.10045.4.3.4": "ECDSA",

	# https://www.rfc-editor.org/rfc/rfc8410.html#section-3
	"1.3.101.112": "EdDSA",
	"1.3.101.113": "EdDSA",
	# https://www.rfc-editor.org/rfc/rfc8708.html#section-3
	"1.2.840.113549.1.9.16.3.17": "LMS",

	# NIST CSOR: DSA/SHA-2/SHA-3, ECDSA/SHA-3, RSA/SHA-3,
	# ML-DSA-44/65/87, and the twelve pure SLH-DSA parameter sets.
	# https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
	"2.16.840.1.101.3.4.3.1": "DSA",
	"2.16.840.1.101.3.4.3.2": "DSA",
	"2.16.840.1.101.3.4.3.3": "DSA",
	"2.16.840.1.101.3.4.3.4": "DSA",
	"2.16.840.1.101.3.4.3.5": "DSA",
	"2.16.840.1.101.3.4.3.6": "DSA",
	"2.16.840.1.101.3.4.3.7": "DSA",
	"2.16.840.1.101.3.4.3.8": "DSA",
	"2.16.840.1.101.3.4.3.9": "ECDSA",
	"2.16.840.1.101.3.4.3.10": "ECDSA",
	"2.16.840.1.101.3.4.3.11": "ECDSA",
	"2.16.840.1.101.3.4.3.12": "ECDSA",
	"2.16.840.1.101.3.4.3.13": "RSASSA-PKCS1-v1_5",
	"2.16.840.1.101.3.4.3.14": "RSASSA-PKCS1-v1_5",
	"2.16.840.1.101.3.4.3.15": "RSASSA-PKCS1-v1_5",
	"2.16.840.1.101.3.4.3.16": "RSASSA-PKCS1-v1_5",
	"2.16.840.1.101.3.4.3.17": "ML-DSA",
	"2.16.840.1.101.3.4.3.18": "ML-DSA",
	"2.16.840.1.101.3.4.3.19": "ML-DSA",
	"2.16.840.1.101.3.4.3.20": "SLH-DSA",
	"2.16.840.1.101.3.4.3.21": "SLH-DSA",
	"2.16.840.1.101.3.4.3.22": "SLH-DSA",
	"2.16.840.1.101.3.4.3.23": "SLH-DSA",
	"2.16.840.1.101.3.4.3.24": "SLH-DSA",
	"2.16.840.1.101.3.4.3.25": "SLH-DSA",
	"2.16.840.1.101.3.4.3.26": "SLH-DSA",
	"2.16.840.1.101.3.4.3.27": "SLH-DSA",
	"2.16.840.1.101.3.4.3.28": "SLH-DSA",
	"2.16.840.1.101.3.4.3.29": "SLH-DSA",
	"2.16.840.1.101.3.4.3.30": "SLH-DSA",
	"2.16.840.1.101.3.4.3.31": "SLH-DSA",
}

# Encryption and key-agreement OIDs that exclude signature inference.
# Generic rsaEncryption and id-ecPublicKey are intentionally absent.
NON_SIGNATURE_OIDS := {
	"1.2.840.113549.1.1.7", # RSAES-OAEP
	"1.3.101.110", # X25519
	"1.3.101.111", # X448
	"2.16.840.1.101.3.4.4.1", # ML-KEM-512
	"2.16.840.1.101.3.4.4.2", # ML-KEM-768
	"2.16.840.1.101.3.4.4.3", # ML-KEM-1024
}

# Known non-agreed families are kept so family metadata can override an
# agreed-looking name. Pre-standard algorithms are not aliases of FIPS schemes.
DIGITAL_SIGNATURE_FAMILIES := {
	"RSASSA-PSS": "RSASSA-PSS",
	"RSA-PSS": "RSASSA-PSS",
	"KCDSA": "KCDSA",
	"Schnorr": "Schnorr",
	"DSA": "DSA",
	"EC-KCDSA": "EC-KCDSA",
	"ECDSA": "ECDSA",
	"EC-DSA": "ECDSA",
	"EC-GDSA": "EC-GDSA",
	"EC-Schnorr": "EC-Schnorr",
	"Deterministic ECDSA": "Deterministic ECDSA",
	"EdDSA": "EdDSA",
	"Ed25519": "EdDSA",
	"Ed448": "EdDSA",
	"ML-DSA": "ML-DSA",
	"XMSS": "XMSS",
	"XMSSMT": "XMSS",
	"LMS": "LMS",
	"HSS": "LMS",
	"HSS/LMS": "LMS",
	"LMS/HSS": "LMS",
	"SLH-DSA": "SLH-DSA",
	"RSASSA-PKCS1": "RSASSA-PKCS1-v1_5",
	"RSASSA-PKCS1-v1_5": "RSASSA-PKCS1-v1_5",
	"RSA-PKCS1-v1_5": "RSASSA-PKCS1-v1_5",
	"Falcon": "Falcon",
	"FN-DSA": "FN-DSA",
	"SM2": "SM2",
	"GOST": "GOST",
	"Dilithium": "Dilithium",
	"CRYSTALS-Dilithium": "Dilithium",
	"SPHINCS+": "SPHINCS+",
}

DIGITAL_SIGNATURE_NAMES := object.union(DIGITAL_SIGNATURE_FAMILIES, {
	"PSS": "RSASSA-PSS",
	"PKCS#1v1.5": "RSASSA-PKCS1-v1_5",
	"RSA-PKCS1-1.5": "RSASSA-PKCS1-v1_5",
	"ECDSAAlgorithm": "ECDSA",
	"ECDSA / EC-DSA": "ECDSA",
	"ECDSA Deterministic": "Deterministic ECDSA",
	"RFC6979 ECDSA": "Deterministic ECDSA",
	"Ed25519ph": "EdDSA",
	"Ed25519ctx": "EdDSA",
	"Ed448ph": "EdDSA",
})
