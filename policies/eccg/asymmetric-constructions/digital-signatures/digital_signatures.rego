package cbom.eccg.asymmetric_constructions.digital_signatures

import data.cbom.eccg.general_helpers.build_finding
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.AGREED_DIGITAL_SIGNATURE_SCHEMES
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.digital_signature_metadata
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.is_agreed_digital_signature_scheme
import data.cbom.eccg.asymmetric_constructions.digital_signatures.helpers.is_digital_signature_component

default compliant := false

compliant if count(findings) == 0

# ECCG-DG-001: Both R and A entries in Section 5.2 are agreed schemes.
# This rule checks scheme recognition only. Parameters and the table's
# implementation notes require separate checks; PKCS#1 v1.5 is admissible.
findings contains finding if {
	some component in input.components
	is_digital_signature_component(component)
	not is_agreed_digital_signature_scheme(component)
	metadata := digital_signature_metadata(component)

	finding := build_finding(
		"ECCG-DG-001",
		"critical",
		sprintf("Digital signature scheme '%s' is not in the ECCG agreed scheme list. The agreed digital signature schemes are: %s.", [metadata.schemeIdentifier, concat(", ", sort(AGREED_DIGITAL_SIGNATURE_SCHEMES))]),
		component,
		metadata,
	)
}
