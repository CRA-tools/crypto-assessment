package cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.constants

# Algorithm identifiers only. Generic id-ecPublicKey does not distinguish
# ECDH from signatures or other EC schemes. No OID is assumed for FrodoKEM,
# DLIES-KEM, or ECIES-KEM; those schemes can be recognized by family/name.
# Parameter-specific OIDs retain their parameter-set name for the size rules.
KEY_ESTABLISHMENT_OIDS := {
	# RFC 3279, Section 2.3.3; PKCS #3 dhKeyAgreement (OpenSSL obj_mac.h).
	# https://www.rfc-editor.org/rfc/rfc3279.html#section-2.3.3
	"1.2.840.10046.2.1": "DH",
	"1.2.840.113549.1.3.1": "DH",
	# https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.2
	"1.3.132.1.12": "EC-DH",
	"1.3.132.1.13": "ECMQV",
	# https://www.rfc-editor.org/rfc/rfc8410.html#section-3
	"1.3.101.110": "X25519",
	"1.3.101.111": "X448",
	# https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
	"2.16.840.1.101.3.4.4.1": "ML-KEM-512",
	"2.16.840.1.101.3.4.4.2": "ML-KEM-768",
	"2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}

# Recognition is distinct from agreement. Known non-agreed families prevent
# a lower-priority agreed-looking name from overriding explicit family data.
KEY_ESTABLISHMENT_FAMILIES := {
	"DH": "DH",
	"DHE": "DH",
	"FFDH": "DH",
	"FFDHE": "DH",
	"DiffieHellman": "DH",
	"DLIES-KEM": "DLIES-KEM",
	"EC-DH": "EC-DH",
	"ECDHE": "EC-DH",
	"ECDHC": "EC-DH",
	"ECIES-KEM": "ECIES-KEM",
	"X25519": "X25519",
	"X448": "X448",
	"ML-KEM": "ML-KEM",
	"FrodoKEM": "FrodoKEM",
	"RSA-KEM": "RSA-KEM",
	"ECMQV": "ECMQV",
	"MQV": "MQV",
	"J-PAKE": "J-PAKE",
	"Kyber": "Kyber",
	"CRYSTALS-Kyber": "Kyber",
	"HQC": "HQC",
	"NTRU": "NTRU",
}

KEY_ESTABLISHMENT_NAMES := object.union(KEY_ESTABLISHMENT_FAMILIES, {
	"FiniteFieldDH": "DH",
	"FiniteFieldDiffieHellman": "DH",
	"ECDiffieHellman": "EC-DH",
	"id-ecDH": "EC-DH",
})

# ECCG notes 64 and 65. These are parameter-set sizes, not security strengths.
RECOMMENDED_ML_KEM_PARAMETER_SIZES := {768, 1024}

RECOMMENDED_FRODOKEM_PARAMETER_SIZES := {976, 1344}
