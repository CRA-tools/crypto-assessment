package cbom.eccg

default compliant := false

compliant if count(findings) == 0

#
# Add section metadata to a finding before returning it from the top-level endpoint.
#
with_policy_location(finding, section, subsection) := enriched if {
    enriched := object.union(finding, {
        "section": section,
        "subsection": subsection,
        "policyPath": sprintf("%s / %s", [section, subsection])
    })
}

#
# Each entry connects a policy package's findings to the section/subsection
# labels that the UI should display.
#
policy_sources := [
    {
        "section": "Symmetric Atomic Primitives",
        "subsection": "Block Ciphers",
        "findings": data.cbom.eccg.symmetric_atomic_primitives.block_ciphers.block_ciphers.findings
    },
    {
        "section": "Symmetric Atomic Primitives",
        "subsection": "Hash Primitives",
        "findings": data.cbom.eccg.symmetric_atomic_primitives.hashes.hash_primitives.findings
    },
    {
        "section": "Symmetric Atomic Primitives",
        "subsection": "XOFs",
        "findings": data.cbom.eccg.symmetric_atomic_primitives.xofs.xofs.findings
    },
    {
        "section": "Symmetric Constructions",
        "subsection": "AES Modes",
        "findings": data.cbom.eccg.symmetric_constructions.symmetric_encryption_schemes.aes_modes.findings
    },
    {
        "section": "Symmetric Constructions",
        "subsection": "Authenticated Encryption",
        "findings": data.cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.authenticated_encryption.findings
    },
    {
        "section": "Symmetric Constructions",
        "subsection": "Mac",
        "findings": data.cbom.eccg.symmetric_constructions.mac.findings
    },
    {
        "section": "Symmetric Constructions",
        "subsection": "Disk Encryption",
        "findings": data.cbom.eccg.symmetric_constructions.disk_encryption.findings
    },
    {
        "section": "Symmetric Constructions",
        "subsection": "Key Combiners",
        "findings": data.cbom.eccg.symmetric_constructions.key_combiners.findings
    },
    {
        "section": "Symmetric Constructions",
        "subsection": "Key Derivation",
        "findings": data.cbom.eccg.symmetric_constructions.key_derivation.findings
    },
    {
        "section": "Symmetric Constructions",
        "subsection": "Key Protection",
        "findings": data.cbom.eccg.symmetric_constructions.key_protection.findings
    },
    {
        "section": "Symmetric Constructions",
        "subsection": "Password Hashing",
        "findings": data.cbom.eccg.symmetric_constructions.password_hashing.findings
    },
    {
        "section": "Asymmetric Constructions",
        "subsection": "Asymmetric Encryption Schemes",
        "findings": data.cbom.eccg.asymmetric_constructions.asymmetric_encryption_schemes.findings
    },
    {
        "section": "Asymmetric Constructions",
        "subsection": "Key Establishment and Key Encapsulation Schemes",
        "findings": data.cbom.eccg.asymmetric_constructions.key_establishment_key_encapsulation.findings
    },
    {
        "section": "Asymmetric Constructions",
        "subsection": "Digital Signature Schemes",
        "findings": data.cbom.eccg.asymmetric_constructions.digital_signatures.findings
    },
    {
        "section": "Asymmetric Atomic Primitives",
        "subsection": "RSA Integer Factorization",
        "findings": data.cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization.findings
    },
    {
        "section": "Asymmetric Atomic Primitives",
        "subsection": "EC DLOG",
        "findings": data.cbom.eccg.asymmetric_atomic_primitives.ec_dlog.findings
    },
    {
        "section": "Asymmetric Atomic Primitives",
        "subsection": "FF DLOG",
        "findings": data.cbom.eccg.asymmetric_atomic_primitives.ff_dlog.findings
    },
    {
        "section": "Random Number Generation",
        "subsection": "Deterministic Random Bit Generator",
        "findings": data.cbom.eccg.random_number_generation.deterministic_random_bit_generator.findings
    },
    #{
    #    "section": "General",
    #    "subsection": "Key Material",
    #    "findings": data.cbom.eccg.general.key_detection.findings
    #}
]

#
# Flatten all package findings into one top-level findings array.
#
findings := [
    with_policy_location(raw, source.section, source.subsection) |
    source := policy_sources[_]
    raw := source.findings[_]
]
