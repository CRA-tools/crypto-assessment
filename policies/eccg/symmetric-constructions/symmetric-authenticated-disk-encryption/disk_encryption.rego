package cbom.eccg.symmetric_constructions.disk_encryption

import data.cbom.eccg.general_helpers.build_finding

import data.cbom.eccg.getter_helpers.get_note
import data.cbom.eccg.getter_helpers.get_component_name_or_empty

import data.cbom.eccg.classifying_helpers.is_symmetric_encryption_scheme
import data.cbom.eccg.classifying_helpers.is_stream_cipher_primitive

import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.symmetric_encryption_scheme_metadata
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_agreed_disk_encryption_scheme
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_cbc_essiv_scheme
import data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption_schemes.helpers.is_xts_scheme

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions" 
SUBSECTION = "Disk-Encryption"

#
# Rule ECCG-DISK-001
# Flag disk-encryption components that are not recognized as accepted
# ECCG disk-encryption schemes.
#
# Accepted / recognized cases:
# - XTS: agreed
# - CBC-ESSIV: admissable
#
# Note:
# CBOM currently does not reliably encode disk-encryption context, so
# this rule should be treated as heuristic and may produce false positives.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    not is_agreed_disk_encryption_scheme(component)

    finding := build_finding(
        "ECCG-DISK-001",
        "low",
        sprintf(
            "Disk encryption scheme '%s' is not in the accepted disk-encryption list. Note that this might be a false positive.",
            [get_component_name_or_empty(component)]
        ),
        component,
        symmetric_encryption_scheme_metadata(component),
    )
}

#
# Rule ECCG-DISK-002
# Flag stream modes used in disk-encryption context.
#
# ECCG Note 9 explains that disk encryption is deterministic because
# the IV/tweak is derived from storage location. Stream modes such as
# CTR and OFB can therefore reuse keystreams when data is rewritten at
# the same location, leaking relationships between plaintexts.
#
# Note:
# This rule depends on heuristic disk-encryption detection because CBOM
# may not explicitly distinguish general encryption from disk encryption.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_stream_cipher_primitive(component)

    note := get_note(SECTION, SUBSECTION, "9-DiskEncStreamMode")


    finding := build_finding(
        "ECCG-DISK-002",
        "low",
        sprintf(
            "Scheme '%s' is a stream-mode construction and is improper for disk encryption. Note that currently it's not possible to detect these schemes accurately through CBOM. There might be some false positives.",
            [get_component_name_or_empty(component)]
        ),
        component,
        object.union(
            symmetric_encryption_scheme_metadata(component),
            {
                "notes": note,
            }
        )
    )
}

#
# Rule ECCG-DISK-003
# Report required operational conditions for XTS.
#
# XTS is an agreed disk-encryption scheme, but it is only secure when
# tweak values are unique for encrypted block positions. ECCG also warns
# that address-derived tweaks require care, especially when logical
# rather than physical addresses are used.
#
# Attached notes:
# - 10-UniqueTweak
# - 11-AddressTweak
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    is_xts_scheme(component)

    note_ids := ["10-UniqueTweak", "11-AddressTweak"]
    notes := [ { "noteId": id, "noteTitle": note.title, "noteText": note.text } | 
        id := note_ids[_] 
        note := get_note(SECTION, SUBSECTION, id) ]

    finding := build_finding(
        "ECCG-DISK-003",
        "warning",
        sprintf(
            "XTS scheme detected: %s. Ensure that every block position across all disks encrypted under the same key has a unique tweak value. If tweaks are derived from storage addresses, verify their uniqueness, particularly when logical rather than physical addresses are used.",
            [get_component_name_or_empty(component)]
        ),
        component,
        object.union(
            symmetric_encryption_scheme_metadata(component),
            {
                "notes": notes,
            }
        )
    )
}

#
# Rule ECCG-DISK-004
# Report CBC-ESSIV-specific operational and security notes.
#
# CBC-ESSIV requires unique sector numbers under a given key and careful
# handling of address-derived sector numbers. ECCG also notes that CBC-
# ESSIV does not provide integrity protection and inherits CBC
# malleability concerns.
#
# Attached notes:
# - 12-UniqueSectorNumber
# - 13-AddressSectorNumber
# - 14-CBCMalleability
#
# Note:
# Because CBC-ESSIV is not directly represented by pyca/cryptography or
# reliably emitted by CBOMkit, this rule is heuristic.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    is_cbc_essiv_scheme(component)

    note_ids := ["12-UniqueSectorNumber", "13-AddressSectorNumber", "14-CBCMalleability"]
    notes := [ { "noteId": id, "noteTitle": note.title, "noteText": note.text } | 
        id := note_ids[_] 
        note := get_note(SECTION, SUBSECTION, id) ]

    finding := build_finding(
        "ECCG-DISK-004",
        "warning",
        sprintf(
            "CBC-ESSIV scheme detected: %s. Ensure that every disk sector has a unique sector number across all disks encrypted under the same key, particularly when sector numbers are derived from logical storage addresses. CBC-ESSIV does not provide integrity protection and is vulnerable to ciphertext manipulation, potentially allowing attackers to produce meaningful changes after decryption. If such attacks are a concern, stronger disk encryption mechanisms should be adopted.",
            [get_component_name_or_empty(component)]
        ),
        component,
        object.union(
            symmetric_encryption_scheme_metadata(component),
            {
                "notes": notes,
            }
        )
    )
}
