package cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.helpers

import data.cbom.eccg.general_helpers.normalize_crypto_identifier
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_crypto_function_or_empty
import data.cbom.eccg.getter_helpers.get_component_asset_type_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_primitive_or_empty

import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.constants.ASYMMETRIC_ENCRYPTION_FAMILIES
import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.constants.ASYMMETRIC_ENCRYPTION_NAMES
import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.constants.ASYMMETRIC_ENCRYPTION_OIDS
import data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.constants.AGREED_ASYMMETRIC_ENCRYPTION_SCHEMES

# Normalize aliases once so case and punctuation differences do not affect
# matching. Constants retain their original casing.
normalized_families := {normalize_crypto_identifier(family): scheme |
	some family, scheme in ASYMMETRIC_ENCRYPTION_FAMILIES
}

normalized_names := {normalize_crypto_identifier(name): scheme |
	some name, scheme in ASYMMETRIC_ENCRYPTION_NAMES
}

# Resolve the scheme using OID, then family, then name. Generic RSA family
# metadata permits a specific name to identify the padding scheme.
get_asymmetric_encryption_scheme_or_empty(component) := scheme if {
	oid := get_component_oid_or_empty(component)
	scheme := ASYMMETRIC_ENCRYPTION_OIDS[oid]
} else := scheme if {
	family := get_component_algorithm_family_or_empty(component)
	scheme := normalized_families[normalize_crypto_identifier(family)]
} else := scheme if {
	scheme := scheme_from_name(get_component_name_or_empty(component))
} else := family if {
	family := get_component_algorithm_family_or_empty(component)
	family != ""
} else := get_component_name_or_empty(component)

# name comes from get_component_name_or_empty: already trimmed and lowercase.
# Exact aliases cover common spellings. Anchored patterns additionally accept
# parameterized CycloneDX and JCA names without matching arbitrary substrings
# such as "not-RSA-OAEP" or "OAEP-wrapper".
scheme_from_name(name) := scheme if {
	scheme := normalized_names[normalize_crypto_identifier(name)]
} else := "RSAES-OAEP" if {
	regex.match(`^(rsa|rsaes)[-_ /]oaep([-_ /]sha-?(1|224|256|384|512))?([-_ /]mgf1)?([-_ /][0-9]+)?$`, name)
} else := "RSAES-OAEP" if {
	regex.match(`^rsa/(ecb|none)/oaep(withsha-?(1|224|256|384|512)andmgf1)?padding$`, name)
} else := "RSAES-PKCS1-v1_5" if {
	regex.match(`^(rsa|rsaes)[-_ /]pkcs1[-_ /](v1[._]?5|1[.]5)([-_ /][0-9]+)?$`, name)
} else := "RSA-NoPadding" if {
	regex.match(`^rsa[-_ /]nopadding([-_ /]|$)`, name)
} else := "ECIES" if {
	regex.match(`^ecies([-_ /]|$)`, name)
} else := "ElGamal" if {
	regex.match(`^elgamal([-_ /]|$)`, name)
} else := "RSA" if {
	regex.match(`^(rsa|rsaes)([-_ /]?[0-9]+)?$`, name)
}

# Explicit primitive metadata takes precedence over names: signatures, KEMs,
# symmetric algorithms, and key material are outside this policy. When the
# primitive is missing, require encryption evidence and exclude signature/KEM
# evidence before inferring that an algorithm belongs to this policy.
is_asymmetric_encryption_component(component) if {
	get_component_asset_type_or_empty(component) == "algorithm"
	get_component_primitive_or_empty(component) == "pke"
} else if {
	get_component_asset_type_or_empty(component) == "algorithm"
	get_component_primitive_or_empty(component) == ""
	not has_signature_function(component)
	not has_non_encryption_family(component)
	not has_kem_name(component)
	has_encryption_evidence(component)
}

# RSA-PKCS1-1.5 can also name a signature. Family metadata disambiguates
# signatures and KEMs when a producer has omitted the primitive field.
# RSASSA-PSS	Digital signatures	signature
# RSASSA-PKCS1-v1_5	Digital signatures	signature
# RSA-KEM	Key encapsulation	kem
has_non_encryption_family(component) if {
	family := normalize_crypto_identifier(get_component_algorithm_family_or_empty(component))
	contains(family, "rsassa")
} else if {
	family := normalize_crypto_identifier(get_component_algorithm_family_or_empty(component))
	family == "rsax931"
} else if {
	family := normalize_crypto_identifier(get_component_algorithm_family_or_empty(component))
	endswith(family, "kem")
}

has_kem_name(component) if {
	name := get_component_name_or_empty(component)
	regex.match(`(^|[-_ /])kem([-_ /]|$)`, name)
}

# OAEP's OID and explicit encryption scheme names/families establish use.
# The generic rsaEncryption OID alone does not: it also identifies keys.
# Encrypt/decrypt functions require RSA context to avoid classifying AES
# or another symmetric algorithm as asymmetric encryption.
has_encryption_evidence(component) if {
	oid := get_component_oid_or_empty(component)
	ASYMMETRIC_ENCRYPTION_OIDS[oid] == "RSAES-OAEP"
} else if {
	family := normalize_crypto_identifier(get_component_algorithm_family_or_empty(component))
	normalized_families[family]
} else if {
	scheme := scheme_from_name(get_component_name_or_empty(component))
	scheme != "RSA"
} else if {
	some fn in get_component_crypto_function_or_empty(component)
	fn in {"encrypt", "decrypt"}
	is_rsa_context(component)
}

has_signature_function(component) if {
	some fn in get_component_crypto_function_or_empty(component)
	fn in {"sign", "verify"}
}

is_rsa_context(component) if {
	get_component_oid_or_empty(component) in ASYMMETRIC_ENCRYPTION_OIDS
} else if {
	normalize_crypto_identifier(get_component_algorithm_family_or_empty(component)) in {"rsa", "rsaes"}
} else if {
	scheme_from_name(get_component_name_or_empty(component)) == "RSA"
}

asymmetric_encryption_metadata(component) := {
	"schemeIdentifier": get_asymmetric_encryption_scheme_or_empty(component),
	"oid": get_component_oid_or_empty(component),
	"algorithmFamily": get_component_algorithm_family_or_empty(component),
}

is_agreed_asymmetric_encryption_scheme(component) if {
	is_asymmetric_encryption_component(component)
	get_asymmetric_encryption_scheme_or_empty(component) in AGREED_ASYMMETRIC_ENCRYPTION_SCHEMES
}

is_oaep_scheme(component) if {
	is_asymmetric_encryption_component(component)
	get_asymmetric_encryption_scheme_or_empty(component) == "RSAES-OAEP"
}

is_pkcs1_v1_5_scheme(component) if {
	is_asymmetric_encryption_component(component)
	get_asymmetric_encryption_scheme_or_empty(component) == "RSAES-PKCS1-v1_5"
}
