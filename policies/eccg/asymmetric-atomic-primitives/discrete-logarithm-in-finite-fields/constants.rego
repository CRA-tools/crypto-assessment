package cbom.eccg.asymmetric_atomic_primitives.discrete_logarithm_in_finite_fields.constants

import data.cbom.eccg.oid_constants.NO_OID

MINIMUM_FF_DLOG_GROUP_BITS := 3072

AGREED_FF_DLOG_GROUP_FAMILIES := {
	"MODP": "RFC3526",
	"FFDHE": "RFC7919",
}

#
# These constants identify potentially FF-DLOG-based
# cryptographic constructions.
#
# They do not establish ECCG compliance.
# ============================================================

# ============================================================
# KEY AGREEMENT
# ============================================================

# Unambiguously finite-field key-agreement families
FF_DLOG_KEY_AGREEMENT_FAMILIES := {
	"DH",
	"FFDH",
	"FF-DLOG",
	"SRP",
}

FF_DLOG_KEY_AGREEMENT_NAMES := {
	"DH",
	"DHE",
	"DiffieHellman",
	"FF-DLOG",
	"FFDH",
	"FFDHE",
	"MODP",
	"FiniteFieldDH",
	"FiniteFieldDiffieHellman",
	"FFMQV",
	"FiniteFieldMQV",
	"SRP-3",
	"SRP-6",
}

# These families support multiple mathematical domains.
FF_DLOG_DOMAIN_DEPENDENT_KEY_AGREEMENT_FAMILIES := {
	"MQV",
	"J-PAKE",
	"SPAKE2",
	"SPAKE2PLUS",
}

# Recognizable finite-field variant names
FF_DLOG_DOMAIN_DEPENDENT_KEY_AGREEMENT_NAMES := {
	"FFMQV",
	"FiniteFieldMQV",
	"J-PAKE-FFDHE",
	"J-PAKE-MODP",
	"SPAKE2-FFDHE",
	"SPAKE2-MODP",
	"SPAKE2+-FFDHE",
	"SPAKE2+-MODP",
}

# ============================================================
# DIGITAL SIGNATURES
# ============================================================

FF_DLOG_SIGNATURE_FAMILIES := {"DSA"}

FF_DLOG_SIGNATURE_NAMES := {
	"DSA",
	"DSA-1024",
	"DSA-2048",
	"DSA-3072",
	# Finite-field Schnorr identifiers
	"FF-Schnorr",
	"Schnorr-FF",
	"FiniteFieldSchnorr",
	# Finite-field ElGamal signatures
	"ElGamal-Signature",
	"FF-ElGamal-Signature",
}

# ============================================================
# PUBLIC-KEY ENCRYPTION
# ============================================================

FF_DLOG_PKE_FAMILIES := {"ElGamal"}

FF_DLOG_PKE_NAMES := {
	"ElGamal",
	"ElGamal-1024",
	"ElGamal-2048",
	"ElGamal-3072",
	"ElGamal-4096",
	"FF-ElGamal",
	"FiniteFieldElGamal",
}

FF_DLOG_CANDIDATE_FAMILIES := ((FF_DLOG_KEY_AGREEMENT_FAMILIES | FF_DLOG_DOMAIN_DEPENDENT_KEY_AGREEMENT_FAMILIES) | FF_DLOG_SIGNATURE_FAMILIES) | FF_DLOG_PKE_FAMILIES

FF_DLOG_CANDIDATE_NAMES := ((FF_DLOG_KEY_AGREEMENT_NAMES | FF_DLOG_DOMAIN_DEPENDENT_KEY_AGREEMENT_NAMES) | FF_DLOG_SIGNATURE_NAMES) | FF_DLOG_PKE_NAMES

#
# Source:
# - https://www.rfc-editor.org/rfc/rfc3526
#
# CycloneDX primitive: key-agree
# CycloneDX algorithm family: FFDH
#
# ECCG agreed groups:
# - 3072 bits: IKE Group 15
# - 4096 bits: IKE Group 16
# - 6144 bits: IKE Group 17
# - 8192 bits: IKE Group 18
#
# Include the 2048-bit group for detection; ECCG-FFDLOG-002 rejects its size.
# ============================================================

MODP_FF_DLOG_SCHEME_NAMES := {
	# RFC 3526 names
	"2048-bit MODP Group",
	"3072-bit MODP Group",
	"4096-bit MODP Group",
	"6144-bit MODP Group",
	"8192-bit MODP Group",
	# Common aliases
	"MODP-2048",
	"MODP-3072",
	"MODP-4096",
	"MODP-6144",
	"MODP-8192",
	"MODP2048",
	"MODP3072",
	"MODP4096",
	"MODP6144",
	"MODP8192",
	# IKE group aliases
	"MODP-Group-14",
	"MODP-Group-15",
	"MODP-Group-16",
	"MODP-Group-17",
	"MODP-Group-18",
}

MODP_FF_DLOG_SCHEME_FAMILIES := {"FFDH"}

# No dedicated ASN.1 OIDs verified for these groups.
MODP_FF_DLOG_SCHEME_OIDS := {
	"MODP-3072": NO_OID,
	"MODP-4096": NO_OID,
	"MODP-6144": NO_OID,
	"MODP-8192": NO_OID,
}

MODP_FF_DLOG_SCHEME_OID_VALUES := {
oid |
	some _, oid in MODP_FF_DLOG_SCHEME_OIDS
	oid != NO_OID
}

# IANA IKE group identifiers (NOT OIDs)
MODP_FF_DLOG_IKE_GROUP_IDS := {
	"MODP-2048": 14,
	"MODP-3072": 15,
	"MODP-4096": 16,
	"MODP-6144": 17,
	"MODP-8192": 18,
}

#
# Source:
# - https://www.rfc-editor.org/rfc/rfc7919
#
# CycloneDX primitive: key-agree
# CycloneDX algorithm family: FFDH
#
# CycloneDX naming pattern:
# FFDH(E)[-{namedGroup}]
#
# ECCG agreed groups:
# - ffdhe3072
# - ffdhe4096
# - ffdhe6144
# - ffdhe8192
#
# Include ffdhe2048 for detection; ECCG-FFDLOG-002 rejects its size.
# ============================================================

FFDHE_FF_DLOG_SCHEME_NAMES := {
	# RFC 7919 names
	"ffdhe2048",
	"ffdhe3072",
	"ffdhe4096",
	"ffdhe6144",
	"ffdhe8192",
	# Common aliases
	"FFDHE2048",
	"FFDHE3072",
	"FFDHE4096",
	"FFDHE6144",
	"FFDHE8192",
	"FFDHE-2048",
	"FFDHE-3072",
	"FFDHE-4096",
	"FFDHE-6144",
	"FFDHE-8192",
	# CycloneDX-style names
	"FFDH-ffdhe2048",
	"FFDH-ffdhe3072",
	"FFDH-ffdhe4096",
	"FFDH-ffdhe6144",
	"FFDH-ffdhe8192",
	"FFDHE-ffdhe2048",
	"FFDHE-ffdhe3072",
	"FFDHE-ffdhe4096",
	"FFDHE-ffdhe6144",
	"FFDHE-ffdhe8192",
}

FFDHE_FF_DLOG_SCHEME_FAMILIES := {"FFDH"}

# No dedicated ASN.1 OIDs verified for these groups.
FFDHE_FF_DLOG_SCHEME_OIDS := {
	"ffdhe3072": NO_OID,
	"ffdhe4096": NO_OID,
	"ffdhe6144": NO_OID,
	"ffdhe8192": NO_OID,
}

FFDHE_FF_DLOG_SCHEME_OID_VALUES := {
oid |
	some _, oid in FFDHE_FF_DLOG_SCHEME_OIDS
	oid != NO_OID
}

# IANA TLS NamedGroup identifiers (NOT OIDs)
FFDHE_FF_DLOG_TLS_GROUP_IDS := {
	"ffdhe2048": 256,
	"ffdhe3072": 257,
	"ffdhe4096": 258,
	"ffdhe6144": 259,
	"ffdhe8192": 260,
}
