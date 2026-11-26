# ECCG Cryptographic Requirements

This catalogue lists the rule IDs, severities, and message variants currently
defined in the Rego policies under [eccg](eccg). Values in square brackets are
substituted from the detected component or policy constants. Literal, unformatted
placeholders in the implementation are identified where applicable.

[eccg/main.rego](eccg/main.rego) combines the active policy findings. The general
key-material rules are implemented separately but are currently excluded from
that combined output. Classification-based and heuristic findings can require
manual review; they do not prove that an implementation satisfies the stated
operational requirements.

## Policy tests

The tests cover individual policy sections, shared helpers, helper type checks,
and the combined assessment. Section tests use complete CycloneDX 1.7 CBOMs.

Run the commands below from the repository root, where `docker-compose.yml` is
located. Docker must be running. The `opa-local` service uses OPA 1.15.1.

Run all section suites, helper tests, integration tests, and regressions:

```bash
docker compose run --rm --no-deps opa-local test /policies --fail-on-empty --timeout 30s
```

Use `--run` to select a suite:

```bash
# All 19 section suites
docker compose run --rm --no-deps opa-local test /policies --run 'section_tests\.' --fail-on-empty

# Additional helper, integration, and regression suites
docker compose run --rm --no-deps opa-local test /policies --run '_test\.' --fail-on-empty

# Identifier matching regressions, including SHA-512/224 and family fallback
docker compose run --rm --no-deps opa-local test /policies --run 'symmetric_identifier_matching_test' --fail-on-empty

# Block cipher policies
docker compose run --rm --no-deps opa-local test /policies --run 'section_tests.block_ciphers'

# Combined assessment and section coverage
docker compose run --rm --no-deps opa-local test /policies --run 'cyclonedx_integration_test'

# Test helper type checks
docker compose run --rm --no-deps opa-local test /policies --run 'test_type_helpers_test'
```

`--run` accepts a regular expression matched against test names. Add
`--fail-on-empty` to fail if the filter matches no tests, or `--verbose` to show
individual test results and failure traces. A successful run ends with
`PASS: <passed>/<total>`. Test failures return a nonzero exit status.
Use `--timeout 30s` when a large parameterized suite exceeds the default test
timeout.

With OPA 1.15.1 installed locally, run:

```bash
opa test policies/eccg --fail-on-empty --timeout 30s
```

From the `policies` directory, use `opa test eccg`. The same `--run` and
`--verbose` options apply.

Rules such as `test_cyclonedx_cases[test_case.name]` are parameterized tests.
`some test_case in cases` selects the fixtures, and `[test_case.name]` gives each
case a named result. For example, the block cipher suite reports `AES 128 bits`,
`AES 192 bits`, and `AES 256 bits` separately. The brackets define the result's
key in the rule head. See [Parameterized tests](tests/README.md#parameterized-tests)
for the rule syntax and an example report.

See [test documentation](tests/README.md) for the section inventory and commands
to validate the fixtures against the official CycloneDX schemas.

## Symmetric Atomic Primitives

### Block Ciphers

- ECCG-BLOCK-001:
    - Severity: critical
    - Message: Block cipher '[cipher]' is not in the agreed Block Cipher primitive list. The agreed Block Ciphers primitives are the following: [agreed block cipher names]

- ECCG-BLOCK-002:
    - Severity: high
    - Message: AES uses a non-agreed key size: [x] bits. The allowed sizes are [128, 192, 256] bits

- ECCG-BLOCK-003:
    - Severity: critical through evaluation year 2027; error after 2027.
    - Message while the legacy period is active: 3DES is considered acceptable only as a legacy mechanism L[2027] and should be phased out.
    - Message after expiry: 3DES was acceptable only as a legacy mechanism L[2027], but that legacy period has expired.
    - Includes the small-block-size and quantum-threat notes. The evaluation year comes from `input.policyEvaluationDate`, falling back to the current time.

- ECCG-BLOCK-004:
    - Severity: critical through evaluation year 2027; error after 2027.
    - Message: 3DES uses a non-agreed key size: [x] bits. Required size is 168 bits. [legacy-status message].
    - The legacy-status message is the corresponding message from ECCG-BLOCK-003.

- ECCG-BLOCK-005:
    - Severity: medium
    - Message: Cipher '[cipher]' uses [x]-bit keying, which is below 192 bits and should be avoided where resistance to quantum attacks is required.

### Hashes

- ECCG-HASH-001:
    - Severity: critical
    - Message: Hash function '[hash-function]' is not in the agreed hash function list. The agreed hash functions are the following [agreed hash names].

- ECCG-HASH-002:
    - Severity: medium
    - Message: Hash function '[hash-function]' has output length [x] bits, which is below the recommended 384 bits for quantum-sensitive contexts

### XOFs

- ECCG-XOF-001:
    - Severity: critical
    - Message: XOF function '[xof-function]' is not in the agreed xof function list. The agreed xof functions are the following [agreed XOF names].

- ECCG-XOF-002:
    - Severity: medium
    - Message: XOF function '[xof-function]' has output length [x] bits, which is below the recommended 256 bits for quantum-sensitive contexts

SHAKE128, SHAKE256, cSHAKE128, and cSHAKE256 are agreed constructions. Numeric
output-length suffixes, such as `SHAKE128-256`, do not change that classification.
SHAKE and cSHAKE remain distinct; the output-length advisory is assessed separately.

## Symmetric Constructions

### Agreed Symmetric Encryption Schemes

- ECCG-SYM-ENC-001:
    - Severity: critical
    - Message: Symmetric encryption scheme '[scheme]' is not in the agreed scheme list [agreed symmetric encryption names].

- ECCG-SYM-ENC-002:
    - Severity: warning
    - Message: Scheme '[scheme]' is only conditionally recommended; standalone use is legacy unless additional integrity is provided. The recommended integrity scheme Encrypt-then-MAC.

- ECCG-SYM-ENC-003:
    - Severity: warning
    - Message for modes requiring an unpredictable IV: [scheme] requires an unpredictable initialization vector (IV). Predictable IVs, including constant IVs, are not accepted.
    - Message for modes requiring a unique IV: [scheme] requires a unique IV or nonce for each encryption operation under the same key.

- ECCG-SYM-ENC-004:
    - Severity: warning
    - Message: GCM scheme detected: [scheme]. Ensure the agreed upon 96 bits of the IV and the appropriate construction NIST SP 800-38D, Section 8.2.1..

- ECCG-SYM-ENC-005:
    - Severity: warning
    - Message: GCM scheme detected: [scheme]. Ensure the plaintext output length 2^32 - 2.
    - The limit described by the rule is a maximum of `2^32 - 2` blocks per encryption invocation, rather than a required exact length.

- ECCG-SYM-ENC-006:
    - Severity: warning
    - Message: GCM scheme detected: [scheme]. The output length of the MAC must be 128.
    - The length is in bits; the rule requires review of tag generation and verification.

### Agreed Disk Encryption Schemes

- ECCG-DISK-001:
    - Severity: low
    - Message: Disk encryption scheme '[scheme]' is not in the accepted disk-encryption list. Note that this might be a false positive.

- ECCG-DISK-002:
    - Severity: low
    - Message: Scheme '[scheme]' is a stream-mode construction and is improper for disk encryption. Note that currently it's not possible to detect these schemes accurately through CBOM. There might be some false positives.

- ECCG-DISK-003:
    - Severity: warning
    - Message: XTS scheme detected: [scheme]. Ensure that every block position across all disks encrypted under the same key has a unique tweak value. If tweaks are derived from storage addresses, verify their uniqueness, particularly when logical rather than physical addresses are used.

- ECCG-DISK-004:
    - Severity: warning
    - Message: CBC-ESSIV scheme detected: [scheme]. Ensure that every disk sector has a unique sector number across all disks encrypted under the same key, particularly when sector numbers are derived from logical storage addresses. CBC-ESSIV does not provide integrity protection and is vulnerable to ciphertext manipulation, potentially allowing attackers to produce meaningful changes after decryption. If such attacks are a concern, stronger disk encryption mechanisms should be adopted.

### Message Authentication Codes

- ECCG-MAC-001:
    - Severity: critical
    - Message: MAC scheme '[scheme]' is not listed in the ECCG agreed or legacy MAC tables. The recommended mac schemes are [agreed MAC names].
    - Severity: warning for the encryption/MAC composition heuristic.
    - Message: Encryption primitive '[encryption]' and MAC primitive '[mac]' occur in close source-code proximity. Verify that the implementation uses an ECCG-agreed composition, meaning Encrypt-then-MAC.
    - Both findings use ECCG-MAC-001. Source proximity does not establish the order of encryption and authentication.

- ECCG-MAC-002:
    - Severity: warning
    - Message: The output [agreed MAC names] must not be truncated to less than 96 bits.
    - GMAC is handled separately by ECCG-GMAC-003.

- ECCG-HMAC-001:
    - Severity: medium
    - Message: For [scheme] in quantum-sensitive contexts, verify that the actual key size is at least 192 bits. The algorithm name and MAC output length do not establish the key size.
    - Applies to HMAC and KMAC; this is an advisory finding and does not verify actual key lengths.

HMAC is agreed as a construction. Its hash variant does not cause an
ECCG-MAC-001 rejection: HMAC-SHA224 and HMAC-SHA512/224 are accepted and retain
the MAC truncation and quantum-context advisories. The standalone hash-primitive
allowlist is assessed separately.

HMAC-SHA1 is accepted only through 2030. From 2031 it produces the critical
ECCG-MAC-001 finding, including when identified through a generic HMAC family.

KMAC128 and KMAC256 remain agreed when their names include an output length,
such as `KMAC128-256`. Other variants, including KMACXOF, are not listed in this
table. The table requires at least 125-bit keys for acceptable HMAC and KMAC128,
and at least 250-bit keys for recommended HMAC and KMAC256. These conditions
require verification of the actual key; recognizing the construction does not
verify them.

- ECCG-CBC-MAC-001:
    - Severity: warning
    - Message: CBC MAC scheme detected: [scheme]. Ensure the outputs follow a fixed input length.

- ECCG-GMAC-001:
    - Severity: warning
    - Message: GMAC scheme detected: [scheme]. Ensure the security of the IV.

- ECCG-GMAC-002:
    - Severity: warning
    - Message: GMAC scheme detected: [scheme]. Ensure the agreed upon 96 bits of the IV and the appropriate construction NIST SP 800-38D, Section 8.2.1..

- ECCG-GMAC-003:
    - Severity: warning
    - Message: GMAC scheme detected: [scheme]. Do not truncate the output tag of GMAC.

### Agreed Symmetric Authenticated Encryption Schemes

- ECCG-SEAS-001:
    - Severity: critical
    - Message: [scheme] is not an agreed Authenticated Encryption scheme.

- ECCG-SEAS-002:
    - Severity: warning
    - Message: [scheme] detected. When using Authenticated Encryption schemes ensure that the challenges are not reused and the challenge bits are 125.

### Agreed Key Protection Schemes

The agreed constructions are RFC5297 SIV and AES Key Wrap (KW and KWP).
Names with key-size suffixes, such as `AES-KW-256` and `AES-SIV-256`, identify
these constructions. AES-GCM-SIV is distinct from RFC5297 SIV and does not
inherit its classification.

- ECCG-KP-001:
    - Severity: medium
    - Message: Key protection scheme '[scheme]' is not in the agreed key-protection list. Agreed schemes are AES Key Wrap, AES Key Wrap with Padding, and SIV. This might be a false positive since there is no way to distinguish key protection schemes from the CBOM.

### Agreed Key Derivation Functions

- ECCG-KDF-001:
    - Severity: medium
    - Message: KDF scheme '[scheme]' is not identified among the listed ECCG constructions: HKDF, PBKDF2, ANSI-X9.63-KDF, and NIST SP800-56A/B/C. This list is not exhaustive; review the construction and its parameters before determining compliance.

- ECCG-KDF-002:
    - Severity: warning
    - Message: PBKDF2 scheme detected: [scheme]. Ensure that the underlying pseudo-random function (PRF) is an agreed cryptographic mechanism. If HMAC is used, verify that the HMAC key length does not exceed the underlying hash function's message block length without considering the security implications. Longer keys are pre-hashed, which may reduce the effective entropy of the key derived using PBKDF2. Note that this might overlap with password-hashing, since they mostly use the same underlying primitives.

Section 3.7 explicitly states that the KDF list is not exhaustive. An unlisted
construction therefore receives a medium finding requiring review. Hash or PRF labels in names
such as `HKDF-BLAKE2b`, `PBKDF2-HMAC-RIPEMD160`, and `X963KDF-SHA224` do not
change which KDF construction is identified. PBKDF2 still requires review of
its PRF under Note 26; recognizing its name does not approve that PRF.

### Agreed Password Hashing Mechanisms

- ECCG-PWH-001:
    - Severity: medium
    - Message: Password hashing mechanism '[scheme]' is not based on the agreed schemes. Note that there is no way to differentiate, whether this is a KDF or a password hash from the CBOM alone. The agreed schemes are: [agreed password hashing schemes]

- ECCG-PWH-002:
    - Severity: warning
    - Message: PBKDF2 password hashing scheme detected: [scheme]. Ensure that the iteration count is set as high as practically possible without impeding legitimate use, to increase resistance against brute-force attacks. Additionally, a cryptographically random salt of at least 128 bits must be generated when the password is registered and stored alongside the password verification value to prevent precomputation attacks.

- ECCG-PWH-003:
    - Severity: warning
    - Message: Argon2id password hashing scheme detected: [scheme]. Ensure that the agreed ECCG parameters are used: 1 iteration, 4 parallel lanes, 2097152 KiB (2 GiB) of memory, a 128-bit salt, and a 256-bit authentication tag.
    - The PBKDF2 and Argon2id parameter findings require manual verification.

### Agreed Key Combiners

- ECCG-KC-001:
    - Severity: warning
    - Message for dependency-based detection: Potential hybrid key combiner detected through dependencies. Verify compliance with ECCG Section 3.9.
    - Message for occurrence-based detection: Potential hybrid key combiner detected through source-code occurrences. Verify compliance with ECCG Section 3.9.
    - Message for a declared combiner primitive: Cryptographic combiner detected, but the construction cannot be verified against ECCG Section 3.9.
    - These heuristics detect multiple key-establishment assets with a combining-related asset. They do not identify the specific combiner construction.
    - All three detection methods use ECCG-KC-001.

## Asymmetric Atomic Primitives

### RSA Integer Factorization

- ECCG-RSA-001:
    - Severity: critical
    - Message: RSA primitive '[scheme]' uses a [x]-bit modulus. The modulus size must be >=3000 bits.
    - Applies when a detected modulus is below 3000 bits. Missing modulus data produces no finding from this rule, and the public-exponent requirement `log2(e) > 16` is not verified by the implementation.

### Agreed FF-DLOG Parameters

- ECCG-FFDLOG-001:
    - Severity: critical
    - Message: FF-DLOG primitive '[scheme]' is not identifiable as an agreed group. Accepted parameter families: [accepted FF-DLOG families].
    - Accepted families are MODP (RFC3526) and FFDHE (RFC7919).

- ECCG-FFDLOG-002:
    - Severity: critical for an undersized MODP/FFDHE group.
    - Message: Group size for [accepted FF-DLOG families] must be >=3072 bits. Detected p=[x] bits.
    - Severity: warning when the group size cannot be determined.
    - Message: Group size for [accepted FF-DLOG families] must be >=3072 bits, but parameterSetIdentifier is missing or does not identify a valid group size.
    - Known groups below 3072 bits are non-compliant regardless of the evaluation date; missing group-size data is inconclusive.

### Agreed Elliptic Curve Parameters

Explicit curve metadata is read from `algorithmProperties.ellipticCurve`,
falling back to the older `algorithmProperties.curve` field used by CBOMkit.
A nonblank string in `ellipticCurve` takes precedence when both fields are
present. Explicit curve metadata is assessed before parameter-set or
algorithm-derived curve inference. For example, `curve: "secp256r1"` identifies
NIST P-256 and receives the SpecialP advisory below.

- ECCG-ECDLOG-001:
    - Severity: critical for a curve outside the allowlist.
    - Message: EC-DLOG primitive detected with elliptic curve [curve], which is not allowed by ECCG-ECDLOG-001. Recommended curves: [recommended curves].
    - Severity: warning when the curve cannot be determined.
    - Message: EC-DLOG primitive detected, but its elliptic curve could not be determined. Supply algorithmProperties.ellipticCurve or algorithmProperties.curve to verify ECCG-ECDLOG-001.
    - Recommended curves: BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1, NIST P-256, NIST P-384, NIST P-521, FRP256v1, Curve25519, and Curve448.

- ECCG-ECDLOG-002:
    - Severity: warning
    - Message: EC-DLOG primitive detected with agreed NIST elliptic curve [curve]. Classified as recommended; ECCG note 39-SpecialP applies.
    - Applies to NIST P-256, P-384, and P-521. Other agreed curves do not produce an informational finding.

## Asymmetric Constructions

### Agreed Asymmetric Encryption Schemes

Implemented in [asymmetric-encryption-schemes](eccg/asymmetric-constructions/asymmetric-encryption-schemes).
Classification uses the first recognized scheme in OID → algorithm family →
component name order. Generic `RSA` family metadata can be refined by a specific
scheme name. Findings include `classificationMethod` and `matchedIdentifier`.

For encryption algorithms, OID `1.2.840.113549.1.1.7` identifies RSAES-OAEP and
`1.2.840.113549.1.1.1` identifies RSAES-PKCS1-v1_5. Signatures, KEMs, and key
material are excluded. A generic RSA identifier without padding information is
inconclusive; identifying an RSA key alone does not establish encryption use.

- ECCG-AS-ENC-001:
    - Severity: info for RSAES-OAEP.
    - Message: RSAES-OAEP (PKCS #1 v2.2 / RFC 8017) detected. Classified as the recommended asymmetric encryption scheme.
    - Severity: warning for RSAES-PKCS1-v1_5.
    - Message: RSAES-PKCS1-v1_5 (PKCS #1 v1.5 / RFC 8017) detected. This asymmetric encryption scheme is admissible but not recommended; RSAES-OAEP (PKCS #1 v2.2 / RFC 8017) is the only recommended asymmetric encryption scheme.
    - Severity: critical for a non-agreed scheme.
    - Message: Asymmetric encryption scheme '[scheme]' is not listed in the ECCG agreed asymmetric encryption scheme table. RSAES-OAEP (PKCS #1 v2.2 / RFC 8017) is the only recommended asymmetric encryption scheme.
    - Severity: warning when RSA encryption padding cannot be determined.
    - Message: RSA asymmetric encryption was detected, but the padding/scheme could not be determined from the CBOM. RSAES-OAEP (PKCS #1 v2.2 / RFC 8017) is the only recommended asymmetric encryption scheme.
    - Severity: warning when a public-key encryption component has no identifiable scheme.
    - Message: Asymmetric encryption was detected, but the scheme could not be determined from the CBOM. RSAES-OAEP (PKCS #1 v2.2 / RFC 8017) is the only recommended asymmetric encryption scheme.
    - OAEP is classified as recommended (`R`); PKCS#1 v1.5 is admissible (`A`). Notes 43-RandomPadding, 44-PaddingAttack, 45-OAEP-PaddingAttack, and 46-QuantumThreat accompany the applicable scheme. Padding generation and decoding require implementation review.

### Agreed Key Establishment and Key Encapsulation Schemes

- ECCG-KEE-001:
    - Severity: critical
    - Message: Key establishment or key encapsulation scheme '[scheme]' is not one of the ECCG recommended schemes. The recommended schemes are DH, DLIES-KEM, EC-DH, ECIES-KEM.

- ECCG-KEE-002:
    - Severity: warning
    - Message: [scheme] is a recommended key establishment or key encapsulation scheme, but participating parties and exchanged key-establishment data must be authenticated.
    - The CBOM identifies the scheme but does not prove that authentication is implemented.

### Agreed Digital Signature Schemes

- ECCG-DG-001:
    - Severity: critical
    - Message: Digital signature scheme '[scheme]' is not in the ECCG agreed scheme list. The agreed digital signature schemes are: [agreed signature schemes].
    - Agreed schemes: RSASSA-PSS, KCDSA, Schnorr, DSA, EC-KCDSA, ECDSA / EC-DSA, EC-GDSA, EC-Schnorr, Deterministic ECDSA, EdDSA, ML-DSA, XMSS, LMS, SLH-DSA, and RSASSA-PKCS1-v1_5.

Both recommended (`R`) and acceptable (`A`) entries are agreed. PKCS#1 v1.5
signatures do not receive a legacy warning from this rule. Hash labels and
parameter suffixes, such as `SHA3-256withECDSA` and `RSA-PSS-SHA3-256`, identify
the signature construction; parameter and primitive checks remain separate.


## General

### Key Material

These rules are defined in [eccg/general/key_detection.rego](eccg/general/key_detection.rego).
Their source entry is commented out in `eccg/main.rego`, so they are not included
in `data.cbom.eccg.findings`. They can be queried separately through
`data.cbom.eccg.general.key_detection.findings`.

Key material is read from
`components[].cryptoProperties.relatedCryptoMaterialProperties`, as specified
by CycloneDX. Its `size` is an integer; algorithm `parameterSetIdentifier`
values are strings.

- ECCG-RSA-KEY-001:
    - Severity: high
    - Message: Private key material '[component]' was detected in the CBOM. Review whether this key is generated, embedded, stored, or otherwise exposed in the source context.

- ECCG-RSA-KEY-002:
    - Severity: info
    - Message: Public key material '[component]' was detected in the CBOM. Public keys are not confidential, but should still be reviewed for lifecycle, trust, and algorithm-size policy.
