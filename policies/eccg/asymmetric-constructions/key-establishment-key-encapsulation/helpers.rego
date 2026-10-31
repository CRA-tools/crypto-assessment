package cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.helpers

import data.cbom.eccg.classifying_helpers.is_kem_primitive
import data.cbom.eccg.classifying_helpers.is_key_agreement_primitive
import data.cbom.eccg.general_helpers.has_parameter_set_identifier
import data.cbom.eccg.general_helpers.normalize_crypto_identifier
import data.cbom.eccg.getter_helpers.get_component_algorithm_family_or_empty
import data.cbom.eccg.getter_helpers.get_component_name_or_empty
import data.cbom.eccg.getter_helpers.get_component_oid_or_empty
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_or_empty

import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.constants.KEY_ESTABLISHMENT_FAMILIES
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.constants.KEY_ESTABLISHMENT_NAMES
import data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.constants.KEY_ESTABLISHMENT_OIDS

normalized_families := {normalize_crypto_identifier(family): scheme |
	some family, scheme in KEY_ESTABLISHMENT_FAMILIES
}

normalized_names := {normalize_crypto_identifier(name): scheme |
	some name, scheme in KEY_ESTABLISHMENT_NAMES
}

# First recognized identifier wins: OID, then family, then name.
get_key_establishment_scheme_or_empty(component) := scheme if {
	identifier := KEY_ESTABLISHMENT_OIDS[get_component_oid_or_empty(component)]
	scheme := scheme_from_name(lower(identifier))
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

# Bounded aliases recognize registry parameterizations without accepting
# arbitrary substrings or treating a hybrid name as a standalone agreed KEM.
scheme_from_name(name) := scheme if {
	scheme := normalized_names[normalize_crypto_identifier(name)]
} else := "DH" if {
	regex.match(`^(dh|dhe|ffdh|ffdhe)([-_ ](ffdhe|modp))?[-_ ]?[0-9]+$`, name)
} else := "DLIES-KEM" if {
	regex.match(`^dlies[-_ ]kem[-_ ](ffdhe|modp)?[-_ ]?[0-9]+$`, name)
} else := "EC-DH" if {
	regex.match(`^ec[-_ ]?dh[ec]?[-_ ]((nist[/_-])?p[-_ ]?(256|384|521)|secp(256r1|384r1|521r1)|brainpoolp(256|384|512)r1|curve(25519|448))$`, name)
} else := "ECIES-KEM" if {
	regex.match(`^ecies[-_ ]kem[-_ ]((nist[/_-])?p[-_ ]?(256|384|521)|secp(256r1|384r1|521r1)|brainpoolp(256|384|512)r1|curve(25519|448))$`, name)
} else := "ML-KEM" if {
	regex.match(`^ml[-_ ]?kem[-_ ]?(512|768|1024)$`, name)
} else := "FrodoKEM" if {
	regex.match(`^frodo[-_ ]?kem[-_ ]?(640|976|1344)([-_ ](aes|shake))?$`, name)
} else := "Kyber" if {
	regex.match(`^(crystals[-_ ])?kyber[-_ ]?(512|768|1024)([-_ ]90s)?$`, name)
}

# Use the shared primitive classifiers for component selection.
is_key_establishment_component(component) if {
	is_kem_primitive(component)
} else if {
	is_key_agreement_primitive(component)
}

# Agreement is composed from the table's primitive groups in helpers.
is_ff_dlog_key_establishment_scheme_name(scheme) if {
	scheme in {"DH", "DLIES-KEM"}
}

is_ec_dlog_key_establishment_scheme_name(scheme) if {
	scheme in {"EC-DH", "ECIES-KEM", "X25519", "X448"}
}

is_lwe_key_establishment_scheme_name(scheme) if {
	scheme in {"ML-KEM", "FrodoKEM"}
}

is_agreed_key_establishment_scheme_name(scheme) if {
	is_ff_dlog_key_establishment_scheme_name(scheme)
} else if {
	is_ec_dlog_key_establishment_scheme_name(scheme)
} else if {
	is_lwe_key_establishment_scheme_name(scheme)
}

is_agreed_key_establishment_scheme(component) if {
	is_key_establishment_component(component)
	is_agreed_key_establishment_scheme_name(get_key_establishment_scheme_or_empty(component))
}

AGREED_KEY_ESTABLISHMENT_SCHEMES := {scheme |
	some _, scheme in KEY_ESTABLISHMENT_NAMES
	is_agreed_key_establishment_scheme_name(scheme)
}

key_establishment_metadata(component) := {
	"schemeIdentifier": get_key_establishment_scheme_or_empty(component),
	"oid": get_component_oid_or_empty(component),
	"algorithmFamily": get_component_algorithm_family_or_empty(component),
}

# Identifiers come from normalized getters or lowercased OID mappings.
# Preserve punctuation when parsing sizes so malformed numeric strings fail.
parameter_size_from_identifier(scheme, identifier) := size if {
	scheme == "ML-KEM"
	regex.match(`^(ml[-_ ]?kem[-_ ]?)?[0-9]+$`, identifier)
	numbers := regex.find_n(`[0-9]+`, identifier, 1)
	size := to_number(numbers[0])
} else := size if {
	scheme == "FrodoKEM"
	regex.match(`^(frodo[-_ ]?kem[-_ ]?)?[0-9]+([-_ ](aes|shake))?$`, identifier)
	numbers := regex.find_n(`[0-9]+`, identifier, 1)
	size := to_number(numbers[0])
} else := ""

# Parameter-specific OIDs are authoritative. Otherwise a nonempty parameter
# string takes precedence over family/name, including malformed strings.
# Missing, blank, and non-string values follow the shared getter's fallback.
# Names from a different scheme cannot supply a parameter size.
get_kem_parameter_size_or_empty(component) := size if {
	scheme := get_key_establishment_scheme_or_empty(component)
	identifier := lower(KEY_ESTABLISHMENT_OIDS[get_component_oid_or_empty(component)])
	size := parameter_size_from_identifier(scheme, identifier)
	size != ""
} else := size if {
	has_parameter_set_identifier(component)
	scheme := get_key_establishment_scheme_or_empty(component)
	size := parameter_size_from_identifier(scheme, get_component_parameter_set_identifier_or_empty(component))
} else := size if {
	scheme := get_key_establishment_scheme_or_empty(component)
	family := get_component_algorithm_family_or_empty(component)
	scheme_from_name(family) == scheme
	size := parameter_size_from_identifier(scheme, family)
	size != ""
} else := size if {
	scheme := get_key_establishment_scheme_or_empty(component)
	name := get_component_name_or_empty(component)
	scheme_from_name(name) == scheme
	size := parameter_size_from_identifier(scheme, name)
	size != ""
} else := ""

kem_parameter_metadata(component) := object.union(key_establishment_metadata(component), {
	"parameterSetIdentifier": get_component_parameter_set_identifier_or_empty(component),
	"parameterSize": get_kem_parameter_size_or_empty(component),
})

kem_parameter_description(component) := "an unknown parameter size" if {
	get_kem_parameter_size_or_empty(component) == ""
} else := sprintf("parameter size %d", [get_kem_parameter_size_or_empty(component)])
