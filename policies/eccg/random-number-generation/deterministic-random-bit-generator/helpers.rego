package cbom.eccg.random_number_generation.deterministic_random_bit_generator.helpers

import data.cbom.eccg.classifying_helpers.is_drbg_primitive
import data.cbom.eccg.general_helpers.normalize_crypto_identifier
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.oid_constants.NO_OID

import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.DRBG_FAMILIES
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.DRBG_NAMES
import data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.constants.DRBG_OIDS

normalized_families := {normalize_crypto_identifier(family): scheme |
	some family, scheme in DRBG_FAMILIES
}

normalized_names := {normalize_crypto_identifier(name): scheme |
	some name, scheme in DRBG_NAMES
}

# First recognized identifier wins: OID, family, name. Unknown or malformed
# identifiers allow fallback; unresolved DRBG components remain non-agreed.
get_drbg_scheme_or_empty(component) := scheme if {
	some scheme, oid in DRBG_OIDS
	oid != NO_OID
	oid == get_component_oid_or_empty(component)
} else := scheme if {
	family := normalize_crypto_identifier(get_component_algorithm_family_or_empty(component))
	scheme := normalized_families[family]
} else := scheme if {
	scheme := scheme_from_name(get_component_algorithm_family_or_empty(component))
} else := scheme if {
	scheme := scheme_from_name(get_component_name_or_empty(component))
} else := family if {
	family := get_component_algorithm_family_or_empty(component)
	family != ""
} else := get_component_name_or_empty(component)

# Match complete identifiers, not arbitrary substrings or wrapper/composite
# names. Getters already supply trimmed, lowercase strings. These parameter
# suffixes identify the construction; they do not certify its parameters.
scheme_from_name(name) := scheme if {
	scheme := normalized_names[normalize_crypto_identifier(name)]
} else := "HMAC_DRBG" if {
	regex.match(`^hmac[-_ ]?drbg[-_ ](sha[-_ ]?(1|224|256|384|512)|sha[-_ ]?512[-_/](224|256))$`, name)
} else := "Hash_DRBG" if {
	regex.match(`^hash[-_ ]?drbg[-_ ](sha[-_ ]?(1|224|256|384|512)|sha[-_ ]?512[-_/](224|256))$`, name)
} else := "CTR_DRBG" if {
	regex.match(`^ctr[-_ ]?drbg[-_ ](aes([-_ ]?(128|192|256))?|tdea|3des)$`, name)
} else := "Dual_EC_DRBG" if {
	regex.match(`^dual[-_ ]?ec[-_ ]?drbg[-_ ](p[-_ ]?)?(256|384|521)$`, name)
}

is_hmac_drbg_scheme_name(scheme) if {
	scheme == "HMAC_DRBG"
}

is_hash_drbg_scheme_name(scheme) if {
	scheme == "Hash_DRBG"
}

is_ctr_drbg_scheme_name(scheme) if {
	scheme == "CTR_DRBG"
}

is_agreed_drbg_scheme_name(scheme) if {
	is_hmac_drbg_scheme_name(scheme)
} else if {
	is_hash_drbg_scheme_name(scheme)
} else if {
	is_ctr_drbg_scheme_name(scheme)
}

is_agreed_drbg_scheme(component) if {
	is_drbg_primitive(component)
	is_agreed_drbg_scheme_name(get_drbg_scheme_or_empty(component))
}

AGREED_DRBG_SCHEMES := {scheme |
	some _, scheme in DRBG_NAMES
	is_agreed_drbg_scheme_name(scheme)
}

drbg_metadata(component) := {
	"schemeIdentifier": get_drbg_scheme_or_empty(component),
	"oid": get_component_oid_or_empty(component),
	"algorithmFamily": get_component_algorithm_family_or_empty(component),
}
