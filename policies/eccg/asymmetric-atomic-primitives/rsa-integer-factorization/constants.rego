package cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.constants

import data.cbom.eccg.oid_constants.NO_OID

MINIMUM_RSA_MODULUS_LENGTH := 3000

#
# Sources:
# - https://www.rfc-editor.org/rfc/rfc8017
# - https://cyclonedx.org/registry/cryptography/
#
# CycloneDX primitives:
# - pke
# - signature
#
# ECCG requirements:
# - Modulus size n >= 3000 bits
# - log2(e) > 16
#
# These identifiers detect RSA usage. They do not establish that an
# encryption padding or signature scheme is recommended.
# ============================================================
RSA_PRIMITIVE_NAMES := {
	# Generic RSA identifiers
	"RSA",
	"RSA-1024",
	"RSA-2048",
	"RSA-3072",
	"RSA-4096",
	"RSA-8192",
	# RSA encryption
	"RSAES-OAEP",
	"RSA-OAEP",
	"RSAES-PKCS1",
	"RSAES-PKCS1-v1_5",
	"RSA-PKCS1-1.5",
	# RSA signatures
	"RSASSA-PSS",
	"RSA-PSS",
	"RSASSA-PKCS1",
	"RSASSA-PKCS1-v1_5",
	"RSA-X9.31",
	"RSA-X931",
	# Signature variants
	"SHA224withRSA",
	"SHA256withRSA",
	"SHA384withRSA",
	"SHA512withRSA",
}

RSA_PRIMITIVE_FAMILIES := {
	"RSA",
	"RSAES-OAEP",
	"RSAES-PKCS1",
	"RSASSA-PSS",
	"RSASSA-PKCS1",
	"RSA-X931",
}

RSA_PRIMITIVE_OIDS := {
	# Generic RSA / PKCS #1
	"rsaEncryption": "1.2.840.113549.1.1.1",
	# RSA encryption
	"RSAES-OAEP": "1.2.840.113549.1.1.7",
	# RSA signatures
	"RSASSA-PSS": "1.2.840.113549.1.1.10",
	# RSA signatures with hashes
	"SHA224withRSA": "1.2.840.113549.1.1.14",
	"SHA256withRSA": "1.2.840.113549.1.1.11",
	"SHA384withRSA": "1.2.840.113549.1.1.12",
	"SHA512withRSA": "1.2.840.113549.1.1.13",
	# No OIDs assigned specifically to these key sizes
	"RSA-1024": NO_OID,
	"RSA-2048": NO_OID,
	"RSA-3072": NO_OID,
	"RSA-4096": NO_OID,
	"RSA-8192": NO_OID,
}

RSA_PRIMITIVE_OID_VALUES := {
oid |
	some _, oid in RSA_PRIMITIVE_OIDS
	oid != NO_OID
}
