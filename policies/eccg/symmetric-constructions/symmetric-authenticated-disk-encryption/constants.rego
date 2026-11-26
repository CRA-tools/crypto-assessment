package cbom.eccg.symmetric_constructions.symmetric_authenticated_disk_encryption.constants

import data.cbom.eccg.oid_constants.NO_OID

SEAS_CHALLENGE_SIZE_REQUIRED_BITS := 125
GCM_INITIALIZATION_VECTOR_REQUIRED_BITS := 96
GCM_MAC_LENGTH_REQUIRED_BITS := 128
GCM_PLAINTEXT_LENGTH_REQUIRED_BITS := "2^32 - 2"
GCM_INITIALIZATION_VECTOR_CONSTRUCTION := "NIST SP 800-38D, Section 8.2.1."

#
# Sources:
# - NIST SP 800-38A, Section 6.1 (ECB):
#   https://doi.org/10.6028/NIST.SP.800-38A
# - NIST CSOR (AES-ECB OIDs):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
# - CycloneDX Cryptography Registry:
#   https://cyclonedx.org/registry/cryptography/
#
# ECB is a block cipher mode of operation.
# These OIDs identify AES-ECB with specific key sizes.
#
# CycloneDX primitive: block-cipher
# CycloneDX algorithm family: AES
# CycloneDX mode: ecb
#
# ECB is not an ECCG-agreed general-purpose encryption
# scheme. It may appear as an internal operation in
# other constructions, such as CBC-ESSIV.
#

ECB_SYMMETRIC_ENCRYPTION_SCHEME_NAMES := {
    "ECB",
    "AES-128-ECB",
    "AES-192-ECB",
    "AES-256-ECB",
}

ECB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES := {
    "AES",
}

ECB_SYMMETRIC_ENCRYPTION_SCHEME_OIDS := {
    "AES-128-ECB": "2.16.840.1.101.3.4.1.1",
    "AES-192-ECB": "2.16.840.1.101.3.4.1.21",
    "AES-256-ECB": "2.16.840.1.101.3.4.1.41",
}

ECB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES := {
    oid | oid := ECB_SYMMETRIC_ENCRYPTION_SCHEME_OIDS[_]
}

#
# Sources:
# - NIST SP 800-38A, Section 6.5 (CTR):
#   https://doi.org/10.6028/NIST.SP.800-38A
# - CycloneDX Cryptography Registry (AES variants):
#   https://cyclonedx.org/registry/cryptography/
# - NIST CSOR (AES OID registrations):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
#
# No AES-CTR OIDs are listed in NIST CSOR.
#
CTR_SYMMETRIC_ENCRYPTION_SCHEME_NAMES := {
    "CTR",
    "AES-128-CTR",
    "AES-192-CTR",
    "AES-256-CTR",
}

CTR_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES := {
    "AES",
}

CTR_SYMMETRIC_ENCRYPTION_SCHEME_OIDS := {
    "CTR": NO_OID,
    "AES-128-CTR": NO_OID,
    "AES-192-CTR": NO_OID,
    "AES-256-CTR": NO_OID,
}

CTR_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES := {
    oid | oid := CTR_SYMMETRIC_ENCRYPTION_SCHEME_OIDS[_]
}

#
# Sources:
# - NIST SP 800-38A, Section 6.4 (OFB):
#   https://doi.org/10.6028/NIST.SP.800-38A
# - NIST CSOR (AES-OFB OIDs):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
# - CycloneDX Cryptography Registry (AES variants):
#   https://cyclonedx.org/registry/cryptography/
#
OFB_SYMMETRIC_ENCRYPTION_SCHEME_NAMES := {
    "OFB",
    "AES-128-OFB",
    "AES-192-OFB",
    "AES-256-OFB",
}

OFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES := {
    "AES",
}

OFB_SYMMETRIC_ENCRYPTION_SCHEME_OIDS := {
    "AES-128-OFB": "2.16.840.1.101.3.4.1.3",
    "AES-192-OFB": "2.16.840.1.101.3.4.1.23",
    "AES-256-OFB": "2.16.840.1.101.3.4.1.43",
}

OFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES := {
    oid | oid := OFB_SYMMETRIC_ENCRYPTION_SCHEME_OIDS[_]
}

# Sources:
# - NIST SP 800-38A, Section 6.2 (CBC):
#   https://doi.org/10.6028/NIST.SP.800-38A
# - NIST CSOR (AES-CBC OIDs):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
# - RFC 3565 (AES-CBC Algorithm Identifiers):
#   https://www.rfc-editor.org/rfc/rfc3565.html
# - CycloneDX Cryptography Registry (AES variants):
#   https://cyclonedx.org/registry/cryptography/
#
CBC_SYMMETRIC_ENCRYPTION_SCHEME_NAMES := {
    "CBC",
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
}

CBC_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES := {
    "AES",
}

CBC_SYMMETRIC_ENCRYPTION_SCHEME_OIDS := {
    "AES-128-CBC": "2.16.840.1.101.3.4.1.2",
    "AES-192-CBC": "2.16.840.1.101.3.4.1.22",
    "AES-256-CBC": "2.16.840.1.101.3.4.1.42",
}

CBC_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES := {
    oid | oid := CBC_SYMMETRIC_ENCRYPTION_SCHEME_OIDS[_]
}

#
# Sources:
# - NIST SP 800-38A Addendum (CBC-CS1, CBC-CS2, CBC-CS3):
#   https://doi.org/10.6028/NIST.SP.800-38A-Add
# - CycloneDX Cryptography Registry (AES-CTS naming):
#   https://cyclonedx.org/registry/cryptography/
# - NIST CSOR (AES OID registrations):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
#
# NIST defines CBC-CS1, CBC-CS2, and CBC-CS3.
# CycloneDX permits CTS as an AES mode variant.
#
# CTS naming alone does not uniquely identify which
# CBC-CS variant is implemented.
#
# No corresponding AES-CBC-CS OIDs are listed in NIST CSOR.
# Ordinary AES-CBC OIDs must not be treated as CBC-CS OIDs.
#
CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_NAMES := {
    "CBC-CS",
    "CBC-CS1",
    "CBC-CS2",
    "CBC-CS3",
    "AES-128-CTS",
    "AES-192-CTS",
    "AES-256-CTS",
}

CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES := {
    "AES",
}

CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_OIDS := {
    "CBC-CS": NO_OID,
    "CBC-CS1": NO_OID,
    "CBC-CS2": NO_OID,
    "CBC-CS3": NO_OID,
    "AES-128-CTS": NO_OID,
    "AES-192-CTS": NO_OID,
    "AES-256-CTS": NO_OID,
}

CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES := {
    oid | oid := CBC_CS_SYMMETRIC_ENCRYPTION_SCHEME_OIDS[_]
}

#
# Sources:
# - NIST SP 800-38A, Section 6.3 (CFB):
#   https://doi.org/10.6028/NIST.SP.800-38A
# - NIST CSOR (AES-CFB OIDs):
#   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
# - CycloneDX Cryptography Registry (AES variants):
#   https://cyclonedx.org/registry/cryptography/
#
# Note: CFB supports different feedback segment sizes.
# CycloneDX recognizes variants such as CFB8 and CFB128.
#
CFB_SYMMETRIC_ENCRYPTION_SCHEME_NAMES := {
    "CFB",
    "AES-128-CFB",
    "AES-192-CFB",
    "AES-256-CFB",
}

CFB_SYMMETRIC_ENCRYPTION_SCHEME_FAMILIES := {
    "AES",
}

CFB_SYMMETRIC_ENCRYPTION_SCHEME_OIDS := {
    "AES-128-CFB": "2.16.840.1.101.3.4.1.4",
    "AES-192-CFB": "2.16.840.1.101.3.4.1.24",
    "AES-256-CFB": "2.16.840.1.101.3.4.1.44",
}

CFB_SYMMETRIC_ENCRYPTION_SCHEME_OID_VALUES := {
    oid | oid := CFB_SYMMETRIC_ENCRYPTION_SCHEME_OIDS[_]
}

# Sources:
# - NIST SP 800-38C:
#   https://doi.org/10.6028/NIST.SP.800-38C
# - RFC 5084, Section 3.1 (AES-CCM OIDs):
#   https://www.rfc-editor.org/rfc/rfc5084.html#section-3.1
# - CycloneDX Cryptography Registry:
#   https://cyclonedx.org/registry/cryptography/
#
# The registered OIDs identify AES-CCM at different key
# sizes, not the generic CCM construction.
#

CCM_AE_ALGORITHM_NAMES := {
    "CCM",
    "AES-128-CCM",
    "AES-192-CCM",
    "AES-256-CCM",
}

CCM_AE_ALGORITHM_FAMILIES := {
    "AES",
}

CCM_AE_ALGORITHM_OIDS := {
    "AES-128-CCM": "2.16.840.1.101.3.4.1.7",
    "AES-192-CCM": "2.16.840.1.101.3.4.1.27",
    "AES-256-CCM": "2.16.840.1.101.3.4.1.47",
}

CCM_AE_ALGORITHM_OID_VALUES := {
    oid | oid := CCM_AE_ALGORITHM_OIDS[_]
}

#
# Sources:
# - NIST SP 800-38D:
#   https://doi.org/10.6028/NIST.SP.800-38D
# - RFC 5084, Section 3.2 (AES-GCM OIDs):
#   https://www.rfc-editor.org/rfc/rfc5084.html#section-3.2
# - CycloneDX Cryptography Registry:
#   https://cyclonedx.org/registry/cryptography/
#
# The registered OIDs identify AES-GCM at different key
# sizes, not the generic GCM construction.
#

GCM_AE_ALGORITHM_NAMES := {
    "GCM",
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
}

GCM_AE_ALGORITHM_FAMILIES := {
    "AES",
}

GCM_AE_ALGORITHM_OIDS := {
    "AES-128-GCM": "2.16.840.1.101.3.4.1.6",
    "AES-192-GCM": "2.16.840.1.101.3.4.1.26",
    "AES-256-GCM": "2.16.840.1.101.3.4.1.46",
}

GCM_AE_ALGORITHM_OID_VALUES := {
    oid | oid := GCM_AE_ALGORITHM_OIDS[_]
}

#
# Sources:
# - ISO/IEC 19772:2020:
#   https://www.iso.org/standard/81550.html
# - CycloneDX Cryptography Registry:
#   https://cyclonedx.org/registry/cryptography/
#
# EAX is an authenticated encryption mode constructed
# from a block cipher.
#
# AES-EAX names below identify AES-specific implementations.
# These are policy recognition names, not separately
# registered CycloneDX naming patterns.
#
# No general-purpose EAX OID verified.
#

EAX_AE_ALGORITHM_NAMES := {
    "EAX",
    "AES-EAX",
    "AES-128-EAX",
    "AES-192-EAX",
    "AES-256-EAX",
}

EAX_AE_ALGORITHM_FAMILIES := {
    "AES",
}

EAX_AE_ALGORITHM_OIDS := {
    "EAX": NO_OID,
    "AES-EAX": NO_OID,
    "AES-128-EAX": NO_OID,
    "AES-192-EAX": NO_OID,
    "AES-256-EAX": NO_OID,
}

EAX_AE_ALGORITHM_OID_VALUES := {
    oid | oid := EAX_AE_ALGORITHM_OIDS[_]
}

#
# Sources:
# - NIST SP 800-38E (XTS-AES):
#   https://doi.org/10.6028/NIST.SP.800-38E
# - IEEE Std 1619 (XTS-AES):
#   https://standards.ieee.org/ieee/1619/11032/
# - IEEE OID registry:
#   https://oid-base.com/get/1.3.111.2.1619.0.1
# - CycloneDX Cryptography Registry:
#   https://cyclonedx.org/registry/cryptography/
#
# XTS-AES uses two independent AES keys.
#
# AES-128-XTS: two 128-bit keys (256 bits total).
# AES-256-XTS: two 256-bit keys (512 bits total).
#
# ECCG classification: Recommended (R).
#
XTS_DISK_ENCRYPTION_SCHEME_NAMES := {
    "XTS",
    "AES-128-XTS",
    "AES-256-XTS",
    "XTS-AES-128",
    "XTS-AES-256",
}

XTS_DISK_ENCRYPTION_SCHEME_FAMILIES := {
    "AES",
}

XTS_DISK_ENCRYPTION_SCHEME_OIDS := {
    "AES-128-XTS": "1.3.111.2.1619.0.1.1",
    "AES-256-XTS": "1.3.111.2.1619.0.1.2",
}

XTS_DISK_ENCRYPTION_SCHEME_OID_VALUES := {
    oid | oid := XTS_DISK_ENCRYPTION_SCHEME_OIDS[_]
}

#
# Sources:
# - Linux Kernel dm-crypt documentation:
#   https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html
# - Linux Kernel fscrypt documentation:
#   https://docs.kernel.org/filesystems/fscrypt.html
# - NIST SP 800-38A (underlying CBC mode):
#   https://doi.org/10.6028/NIST.SP.800-38A
# - CycloneDX Cryptography Registry:
#   https://cyclonedx.org/registry/cryptography/
#
# CBC-ESSIV combines CBC encryption with ESSIV-based
# initialization vector generation.
#
# Linux dm-crypt uses names such as:
#   aes-cbc-essiv:sha256
#
# The hash identifies the ESSIV IV-key derivation hash.
#
# No standalone CBC-ESSIV OID has been verified.
# Ordinary AES-CBC OIDs must not be treated as identifiers
# of the complete CBC-ESSIV construction.
#
# ECCG classification: Acceptable (A).
#
CBC_ESSIV_DISK_ENCRYPTION_SCHEME_NAMES := {
    "CBC-ESSIV",
    "AES-CBC-ESSIV",
    "aes-cbc-essiv:sha256",
}

CBC_ESSIV_DISK_ENCRYPTION_SCHEME_FAMILIES := {
    "AES",
}

CBC_ESSIV_DISK_ENCRYPTION_SCHEME_OIDS := {
    "CBC-ESSIV": NO_OID,
    "AES-CBC-ESSIV": NO_OID,
    "aes-cbc-essiv:sha256": NO_OID,
}

CBC_ESSIV_DISK_ENCRYPTION_SCHEME_OID_VALUES := {
    oid | oid := CBC_ESSIV_DISK_ENCRYPTION_SCHEME_OIDS[_]
}

