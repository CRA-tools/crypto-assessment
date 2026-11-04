package cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.constants

# RFC 8017, Appendix A.2.1/A.2.2:
# https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.2
# rsaEncryption also identifies RSA keys. Interpret it as PKCS#1 v1.5
# only after the component has been identified as an encryption algorithm.
ASYMMETRIC_ENCRYPTION_OIDS := {
	"1.2.840.113549.1.1.7": "RSAES-OAEP",
	"1.2.840.113549.1.1.1": "RSAES-PKCS1-v1_5",
}

# CycloneDX algorithm families and common scheme aliases:
# https://cyclonedx.org/registry/cryptography/
# ECIES and ElGamal are recognizable but not agreed. Keeping them here lets
# explicit family metadata take precedence over a misleading RSA scheme name.
ASYMMETRIC_ENCRYPTION_FAMILIES := {
	"RSAES-OAEP": "RSAES-OAEP",
	"RSA-OAEP": "RSAES-OAEP",
	"RSAES-PKCS1": "RSAES-PKCS1-v1_5",
	"RSAES-PKCS1-v1_5": "RSAES-PKCS1-v1_5",
	"RSA-PKCS1-v1_5": "RSAES-PKCS1-v1_5",
	"ECIES": "ECIES",
	"ElGamal": "ElGamal",
}

# Exact aliases are normalized before lookup. Parameterized names are
# handled separately with bounded patterns in scheme_from_name.
ASYMMETRIC_ENCRYPTION_NAMES := {
	"RSAES-OAEP": "RSAES-OAEP",
	"RSA-OAEP": "RSAES-OAEP",
	"OAEP": "RSAES-OAEP",
	"RSAES-PKCS1": "RSAES-PKCS1-v1_5",
	"RSAES-PKCS1-v1_5": "RSAES-PKCS1-v1_5",
	"RSA-PKCS1-v1_5": "RSAES-PKCS1-v1_5",
	"RSA-PKCS1-1.5": "RSAES-PKCS1-v1_5",
	"PKCS1v15": "RSAES-PKCS1-v1_5",
	"PKCS1Padding": "RSAES-PKCS1-v1_5",
	"RSA/ECB/PKCS1Padding": "RSAES-PKCS1-v1_5",
	"RSA/None/PKCS1Padding": "RSAES-PKCS1-v1_5",
	"RSA/ECB/NoPadding": "RSA-NoPadding",
	"RSA/None/NoPadding": "RSA-NoPadding",
	"RSA-NoPadding": "RSA-NoPadding",
	"ECIES": "ECIES",
	"ElGamal": "ElGamal",
}

AGREED_ASYMMETRIC_ENCRYPTION_SCHEMES := {
	"RSAES-OAEP",
	"RSAES-PKCS1-v1_5",
}
