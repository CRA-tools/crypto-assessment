package cbom.eccg.asymmetric_constructions.digital_signatures.helpers

import data.cbom.eccg.general_helpers.normalize_crypto_identifier
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_asset_type_or_empty
import data.cbom.eccg.getter_helpers.get_component_crypto_function_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty

import data.cbom.eccg.asymmetric_constructions.digital_signatures.constants.DIGITAL_SIGNATURE_FAMILIES
import data.cbom.eccg.asymmetric_constructions.digital_signatures.constants.DIGITAL_SIGNATURE_NAMES
import data.cbom.eccg.asymmetric_constructions.digital_signatures.constants.DIGITAL_SIGNATURE_OIDS
import data.cbom.eccg.asymmetric_constructions.digital_signatures.constants.NON_SIGNATURE_OIDS

normalized_families := {normalize_crypto_identifier(family): scheme |
	some family, scheme in DIGITAL_SIGNATURE_FAMILIES
}

normalized_names := {normalize_crypto_identifier(name): scheme |
	some name, scheme in DIGITAL_SIGNATURE_NAMES
}

# First recognized identifier wins: OID, then family, then name.
# Generic RSA/EC metadata cannot determine a signature scheme; a specific
# name may supply it. Unknown or malformed identifiers allow fallback.
get_digital_signature_scheme_or_empty(component) := scheme if {
	scheme := DIGITAL_SIGNATURE_OIDS[get_component_oid_or_empty(component)]
} else := scheme if {
	family := normalize_crypto_identifier(get_component_algorithm_family_or_empty(component))
	scheme := normalized_families[family]
} else := scheme if {
	scheme := scheme_from_name(get_component_name_or_empty(component))
} else := family if {
	family := get_component_algorithm_family_or_empty(component)
	family != ""
} else := get_component_name_or_empty(component)

# Identify the construction independently of hash, curve, and key parameters.
# Getters supply lowercase, trimmed strings.
scheme_from_name(name) := scheme if {
	scheme := normalized_names[normalize_crypto_identifier(name)]
} else := "ML-DSA" if {
	regex.match(`^ml[-_ ]?dsa[-_ ]?(44|65|87)$`, name)
} else := "SLH-DSA" if {
	regex.match(`^slh[-_ ]?dsa[-_ ](sha2|shake)[-_ ](128|192|256)[sf]$`, name)
} else := "XMSS" if {
	matches_signature_name(name, "xmss(mt)?")
} else := "LMS" if {
	matches_signature_name(name, "(hss[-_/])?lms")
} else := "RSASSA-PSS" if {
	matches_signature_name(name, "(rsa|rsassa)[-_ ]?pss")
} else := "RSASSA-PSS" if {
	regex.match(`^[a-z0-9][a-z0-9._/-]*withrsa(andmgf1|/pss)$`, name)
} else := "RSASSA-PKCS1-v1_5" if {
	regex.match(`^[a-z0-9][a-z0-9._/-]*withrsa(encryption)?$`, name)
} else := "RSASSA-PKCS1-v1_5" if {
	matches_signature_name(name, "(rsa|rsassa)[-_ ]pkcs#?1[-_ ](v1[._]?5|1[.]5)")
} else := "Deterministic ECDSA" if {
	matches_signature_name(name, "(deterministic[-_ ]ecdsa|ecdsa[-_ ]deterministic|rfc6979[-_ ]ecdsa)")
} else := "ECDSA" if {
	regex.match(`^[a-z0-9][a-z0-9._/-]*withecdsa$`, name)
} else := "ECDSA" if {
	matches_signature_name(name, "ec[-_ ]?dsa")
} else := "DSA" if {
	regex.match(`^[a-z0-9][a-z0-9._/-]*withdsa$`, name)
} else := "DSA" if {
	matches_signature_name(name, "dsa")
} else := "KCDSA" if {
	matches_signature_name(name, "kcdsa")
} else := "Schnorr" if {
	matches_signature_name(name, "schnorr")
} else := "EC-KCDSA" if {
	matches_signature_name(name, "ec[-_ ]?kcdsa")
} else := "EC-GDSA" if {
	matches_signature_name(name, "ec[-_ ]?gdsa")
} else := "EC-Schnorr" if {
	matches_signature_name(name, "ec[-_ ]?schnorr")
} else := "EdDSA" if {
	matches_signature_name(name, "(eddsa|ed(25519|448)(ph|ctx)?)")
}

matches_signature_name(name, construction_pattern) if {
	pattern := sprintf(`^(%s)([-_/ ][a-z0-9][a-z0-9._/ -]*)?$`, [construction_pattern])
	regex.match(pattern, name)
}

# Explicit primitive and asset type take precedence over inference. When a
# producer omits the primitive, signature identifiers or sign/verify functions
# establish context. Encryption/KEM functions prevent name-based inference.
is_digital_signature_component(component) if {
	get_component_asset_type_or_empty(component) == "algorithm"
	get_component_primitive_or_empty(component) == "signature"
} else if {
	get_component_asset_type_or_empty(component) == "algorithm"
	get_component_primitive_or_empty(component) == ""
	not has_non_signature_function(component)
	not has_non_signature_identifier(component)
	has_signature_evidence(component)
}

has_non_signature_function(component) if {
	some fn in get_component_crypto_function_or_empty(component)
	fn in {"encrypt", "decrypt", "encapsulate", "decapsulate", "keyderive"}
}

# A recognized signature OID still outranks a contradictory family. Otherwise,
# encryption/key-agreement identifiers cannot be reinterpreted via the name.
# Generic rsaEncryption and id-ecPublicKey remain neutral.
has_non_signature_identifier(component) if {
	not DIGITAL_SIGNATURE_OIDS[get_component_oid_or_empty(component)]
	family := normalize_crypto_identifier(get_component_algorithm_family_or_empty(component))
	regex.match(`^(rsaes.*|.*kem|ecies|elgamal|ecdh|ecdhc|ecdhcofactor|dh|x25519|x448)$`, family)
} else if {
	get_component_oid_or_empty(component) in NON_SIGNATURE_OIDS
}

has_signature_evidence(component) if {
	DIGITAL_SIGNATURE_OIDS[get_component_oid_or_empty(component)]
} else if {
	family := normalize_crypto_identifier(get_component_algorithm_family_or_empty(component))
	normalized_families[family]
} else if {
	scheme_from_name(get_component_name_or_empty(component))
} else if {
	some fn in get_component_crypto_function_or_empty(component)
	fn in {"sign", "verify"}
}

# Classify resolved scheme names by the primitive groups in ECCG Section 5.2.
# These predicates accept canonical scheme names, after OID/family/name
# resolution, so contradictory lower-priority identifiers cannot change groups.
is_rsa_signature_scheme_name(scheme) if {
	scheme in {"RSASSA-PSS", "RSASSA-PKCS1-v1_5"}
}

is_ff_dlog_signature_scheme_name(scheme) if {
	scheme in {"KCDSA", "Schnorr", "DSA"}
}

is_ec_dlog_signature_scheme_name(scheme) if {
	scheme in {"EC-KCDSA", "ECDSA", "EC-GDSA", "EC-Schnorr", "Deterministic ECDSA", "EdDSA"}
}

is_lwe_signature_scheme_name(scheme) if {
	scheme == "ML-DSA"
}

is_hash_based_signature_scheme_name(scheme) if {
	scheme in {"XMSS", "LMS", "SLH-DSA"}
}

is_agreed_signature_scheme_name(scheme) if {
	is_rsa_signature_scheme_name(scheme)
} else if {
	is_ff_dlog_signature_scheme_name(scheme)
} else if {
	is_ec_dlog_signature_scheme_name(scheme)
} else if {
	is_lwe_signature_scheme_name(scheme)
} else if {
	is_hash_based_signature_scheme_name(scheme)
}

is_agreed_digital_signature_scheme(component) if {
	is_digital_signature_component(component)
	is_agreed_signature_scheme_name(get_digital_signature_scheme_or_empty(component))
}

# Derive the names used in findings through the same classification predicates.
# Recognition constants also contain non-agreed names, which are filtered out.
AGREED_DIGITAL_SIGNATURE_SCHEMES := {scheme |
	some _, scheme in DIGITAL_SIGNATURE_NAMES
	is_agreed_signature_scheme_name(scheme)
}

digital_signature_metadata(component) := {
	"schemeIdentifier": get_digital_signature_scheme_or_empty(component),
	"oid": get_component_oid_or_empty(component),
	"algorithmFamily": get_component_algorithm_family_or_empty(component),
}
