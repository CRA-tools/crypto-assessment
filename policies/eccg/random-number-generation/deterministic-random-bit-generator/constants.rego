package cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants

import data.cbom.eccg.oid_constants.NO_OID

# Scheme-to-OID mappings use the shared placeholder until a scheme-specific
# OID is verified. HMAC/hash/AES OIDs identify different primitives.
DRBG_OIDS := {
	"HMAC_DRBG": NO_OID,
	"Hash_DRBG": NO_OID,
	"CTR_DRBG": NO_OID,
}

# Recognition includes non-agreed families so a known non-agreed family takes
# precedence over an agreed-looking component name. Agreement lives in helpers.
DRBG_FAMILIES := {
	"HMAC_DRBG": "HMAC_DRBG",
	"Hash_DRBG": "Hash_DRBG",
	"CTR_DRBG": "CTR_DRBG",
	"Dual_EC_DRBG": "Dual_EC_DRBG",
	"DualEC": "Dual_EC_DRBG",
	"Fortuna": "Fortuna",
	"Yarrow": "Yarrow",
	"MT19937": "MT19937",
	"Mersenne Twister": "MT19937",
}

DRBG_NAMES := DRBG_FAMILIES

MIN_SEED_ENTROPY_BITS := 125
QUANTUM_MIN_SEED_ENTROPY_BITS := 188
QUANTUM_MIN_CTR_KEY_BITS := 192
