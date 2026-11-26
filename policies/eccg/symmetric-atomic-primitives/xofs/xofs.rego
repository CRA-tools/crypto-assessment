package cbom.eccg.symmetric_atomic_primitives.xofs.xofs

import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.classifying_helpers.is_xof_primitive
import data.cbom.eccg.getter_helpers.get_note
import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.symmetric_atomic_primitives.xofs.helpers.is_agreed_xof_component
import data.cbom.eccg.symmetric_atomic_primitives.xofs.helpers.xof_primitive_metadata
import data.cbom.eccg.symmetric_atomic_primitives.xofs.helpers.is_xof_output_size_above_quantum_sensitive_threshold
import data.cbom.eccg.symmetric_atomic_primitives.xofs.helpers.AGREED_XOF_ALGORITHM_NAMES

import data.cbom.eccg.symmetric_atomic_primitives.xofs.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF

default compliant := true

compliant if count(findings) == 0

NOTE_SECTION := "Symmetric-Atomic-Primitives"
NOTE_SUBSECTION := "XOFs"

#
# Rule ECCG-XOF-001
# Any xof not in the agreed list should be flagged.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_xof_primitive(component)
    not is_agreed_xof_component(component)
    finding := build_finding(
        "ECCG-XOF-001",
        "critical",
        sprintf("XOF function '%s' is not in the agreed xof function list. The agreed xof functions are the following %s.", [get_component_name_or_empty(component), AGREED_XOF_ALGORITHM_NAMES]),
        component,
        xof_primitive_metadata(component),
    )
}

#
# Rule ECCG-XOF-002
# In quantum-sensitive contexts, xof output below 256 bits should be avoided.
# parameterSetIdentifier is not the actual xofSize but the maximum security bits
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_agreed_xof_component(component)
    not is_xof_output_size_above_quantum_sensitive_threshold(component)
    note := get_note(NOTE_SECTION, NOTE_SUBSECTION, "4-QuantumThreat")

    finding := build_finding(
        "ECCG-XOF-002",
        "medium",
        sprintf(
            "XOF function '%s' has output length %v bits, which is below the recommended %d bits for quantum-sensitive contexts",
            [get_component_name_or_empty(component), get_component_parameter_set_identifier_to_number_or_negative_one(component), MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_XOF]
        ),
        component,
        object.union(
            xof_primitive_metadata(component),
            {
                "notes": note,
            }
        )
    )
}
