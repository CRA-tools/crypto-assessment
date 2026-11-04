package cbom.eccg.symmetric_atomic_primitives.block_ciphers.block_ciphers

import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.general_helpers.build_finding
import data.cbom.eccg.general_helpers.legacy_marker_status
import data.cbom.eccg.general_helpers.legacy_status_severity
import data.cbom.eccg.general_helpers.legacy_status_message
import data.cbom.eccg.general_helpers.evaluation_year

import data.cbom.eccg.classifying_helpers.is_block_cipher_primitive

import data.cbom.eccg.getter_helpers.get_component_parameter_set_identifier_to_number_or_negative_one
import data.cbom.eccg.getter_helpers.get_note

import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.TRIPLE_DES_REQUIRED_KEY_BITS
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.TRIPLE_DES_LEGACY_MARKER
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.AES_ALLOWED_KEY_SIZES
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.constants.MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_BLOCK_CIPHER

import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.is_aes_component
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.is_3des_component
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.block_cipher_metadata
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.is_agreed_block_cipher_component
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.is_allowed_aes_key_size
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.is_block_cipher_key_size_above_quantum_sensitive_threshold
import data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.helpers.AGREED_BLOCK_CIPHER_ALGORITHM_NAMES


#
# Overall result:
# - compliant = true  => no findings were produced
# - compliant = false => at least one finding exists
#
default compliant := true

compliant if count(findings) == 0

NOTE_SECTION := "Symmetric-Atomic-Primitives"
NOTE_SUBSECTION := "Block-Ciphers"

#
# Rule ECCG-BLOCK-001
# AES is the only recommended block cipher 
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_block_cipher_primitive(component)
    not is_agreed_block_cipher_component(component)

    finding := build_finding(
        "ECCG-BLOCK-001",
        "critical",
        sprintf("Block cipher '%s' is not in the agreed Block Cipher primitive list. The agreed Block Ciphers primitives are the following: %s", [get_component_name_or_empty(component), AGREED_BLOCK_CIPHER_ALGORITHM_NAMES]),
        component,
        block_cipher_metadata(component),
    )
}

#
# Rule ECCG-BLOCK-002
# AES is only agreed with key sizes 128, 192, or 256 bits.
# the key sizes here are the maximum security bits 
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_aes_component(component)
    not is_allowed_aes_key_size(component)

    finding := build_finding(
        "ECCG-BLOCK-002",
        "high",
        sprintf(
            "AES uses a non-agreed key size: %v bits. The allowed sizes are %v bits",
            [get_component_parameter_set_identifier_to_number_or_negative_one(component), AES_ALLOWED_KEY_SIZES]
        ),
        component,
        object.union(
            block_cipher_metadata(component),
            {
                "allowedKeySizes": AES_ALLOWED_KEY_SIZES
            }
        )
    )
}

#
# Rule ECCG-BLOCK-003
# Even when 3DES has the expected size, it is still legacy-only.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_3des_component(component)

    status := legacy_marker_status(TRIPLE_DES_LEGACY_MARKER)
    severity := legacy_status_severity(status)
    message := legacy_status_message("3DES", TRIPLE_DES_LEGACY_MARKER, status)

    note_ids := ["2-SmallBlockSize", "3-QuantumThreat"]
    notes := [ { "noteId": id, "noteTitle": note.title, "noteText": note.text } | 
        id := note_ids[_] 
        note := get_note(NOTE_SECTION, NOTE_SUBSECTION, id) ]

    finding := build_finding(
        "ECCG-BLOCK-003",
        severity,
        message,
        component,
        object.union(
            block_cipher_metadata(component),  
            {
                "status": status,
                "legacyMarker": TRIPLE_DES_LEGACY_MARKER,
                "evaluationYear": evaluation_year,
                "notes": notes,
            }
        )
    )
}

#
# Rule ECCG-BLOCK-004
# Triple-DES / 3DES must use a 168-bit key size according to the rule set.
# this is the maximum security bits not the key size
#
findings contains finding if {
    component := input.components[component_index]

    is_3des_component(component)

    status := legacy_marker_status(TRIPLE_DES_LEGACY_MARKER)
    severity := legacy_status_severity(status)
    message := legacy_status_message("3DES", TRIPLE_DES_LEGACY_MARKER, status)
    # these are the maximum security bits not the key bits
    get_component_parameter_set_identifier_to_number_or_negative_one(component) != TRIPLE_DES_REQUIRED_KEY_BITS

    finding := build_finding(
        "ECCG-BLOCK-004",
        severity,
        sprintf(
            "3DES uses a non-agreed key size: %v bits. Required size is %d bits. %s.",
            [
                get_component_parameter_set_identifier_to_number_or_negative_one(component), 
                TRIPLE_DES_REQUIRED_KEY_BITS, 
                message
            ],
        ),
        component,
        object.union(
            block_cipher_metadata(component),
            {
                "status": status,
                "legacyMarker": TRIPLE_DES_LEGACY_MARKER,
                "evaluationYear": evaluation_year,
                "requiredKeyBits": TRIPLE_DES_REQUIRED_KEY_BITS,
            }
        )
    )
}


#
# Rule ECCG-BLOCK-005
# In quantum-sensitive contexts, agreed block ciphers below maximum security 192 bits are discouraged.
#
findings contains finding if {

    some component_index
    component := input.components[component_index]

    is_agreed_block_cipher_component(component)
    not is_block_cipher_key_size_above_quantum_sensitive_threshold(component)

    note_id :=  "3-QuantumThreat"

    note := get_note(NOTE_SECTION, NOTE_SUBSECTION, note_id)

    finding := build_finding(
        "ECCG-BLOCK-005",
        "medium",
        sprintf(
            "Cipher '%s' uses %v-bit keying, which is below %d bits and should be avoided where resistance to quantum attacks is required.",
            [get_component_name_or_empty(component), get_component_parameter_set_identifier_to_number_or_negative_one(component), MINIMUM_RECOMMENDED_BITS_FOR_QUANTUM_SENSITIVE_CONTEXT_BLOCK_CIPHER]
        ),
        component,
        object.union(
            block_cipher_metadata(component),
            {
                "notes": note,
            }
        )
    )
}
