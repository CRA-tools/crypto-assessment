# Demo code for test assessments

**Use the sample code in [`demo/code`](code) to run a test assessment or get
familiar with the CRACY Cryptographic Assessment Tool.** The examples let you
try the scanning workflow, inspect the generated CBOM, and explore policy and
source-code findings before assessing your own project.

To try it, enter `https://github.com/CRA-tools/crypto-assessment.git` as the
repository URL in the frontend, set **Scan path** to `demo/code`, and press
**Check compliance**. Review the result, then select **Show findings** to
explore the details. See the [main usage guide](../README.md#usage) for the
full workflow.

The sections below explain example findings and their severities to help you
understand the assessment results.

# Severities 

- `critical`: Serious issue that should be prioritized immediately; usually indicates obsolete, non-agreed, or strongly non-compliant cryptographic usage.
- `high`: Important issue that should be fixed or reviewed soon; often indicates legacy or risky cryptographic usage in the near future.
- `medium`: Moderate issue that may be acceptable in some contexts but requires review, especially for sensitive or quantum-sensitive use cases.
- `low`: Minor issue or weak signal that should be reviewed but is not usually urgent.
- `warning`: Informational policy warning where the usage may be context-dependent or requires manual review.
- `info`: Non-violating or explanatory finding, often used to report detected recommended mechanisms or limitations of the evaluation.

# Symmetric Atomic Primitives 

## ECCG-BLOCK-001: Non-Agreed Block Cipher

**Severity: Critical**

ECCG-BLOCK-001 detects block cipher primitives that are not in the agreed ECCG block cipher list. The agreed list currently includes AES and 3DES. Any detected block cipher outside that list is reported as non-compliant.

For example, the following pyca/cryptography code can produce a CBOM entry for Blowfish:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"K" * 16
iv = b"I" * 8

cipher = Cipher(
    algorithms.Blowfish(key),
    modes.CBC(iv),
)
```

## ECCG-BLOCK-003: Non-Agreed 3DES Key Size

**Severity: high**

ECCG-BLOCK-003 detects 3DES components whose detected key size does not match the expected ECCG value:

```
requiredKeyBits = 168
```

For example, the following pyca/cryptography code can produce a 3DES CBOM entry:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"1234567890ABCDEF"
iv = b"12345678"

cipher = Cipher(
    algorithms.TripleDES(key),
    modes.CBC(iv),
)
```

3DES uses a non-agreed key size: 64 bits. Required size is 168 bits

In practice, this rule is sensitive to how CBOMkit populates parameterSetIdentifier. For block ciphers, the value may reflect the block size, mode parameter, or another algorithm identifier rather than the actual key size. In the example finding, 3DES is reported with 64 bits, which likely reflects the 64-bit block size rather than the effective 3DES keying material. Because of that, key-size findings for block ciphers should be treated as useful signals but not always definitive. Manual review may be required to confirm the actual key length used in source code.

## ECCG-BLOCK-004: 3DES Legacy and Small Block Size Warning

**Severity: high**

ECCG-BLOCK-004 detects any use of 3DES. Even if the detected 3DES component appears to use the expected key size, the rule still reports it because 3DES is legacy-bound and has structural limitations that make it unsuitable for new use.

The rule is triggered whenever a CBOM component is identified as 3DES:

```rego
is_3des_component(component)
```

For example, the following pyca/cryptography code can produce a CBOM entry for 3DES:

```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"1234567890ABCDEF"
iv = b"12345678"

cipher = Cipher(
    algorithms.TripleDES(key),
    modes.CBC(iv),
)
```

The rule attaches ECCG notes related to:

```
2-SmallBlockSize
3-QuantumThreat
```

The small-block-size note is important because 3DES has a 64-bit block size. This creates practical limits for the safe amount of data that can be encrypted under the same key, especially compared with modern 128-bit block ciphers such as AES.

The quantum-threat note is included because 3DES does not meet the preferred security margin for quantum-sensitive contexts. As a result, the rule reports 3DES as a high-severity finding even when other 3DES-specific checks, such as key-size checks, may also fire.

## ECCG-BLOCK-005: Block Cipher Below 192 Bits in Quantum-Sensitive Contexts

**Severity: medium** 

ECCG-BLOCK-005 detects agreed block cipher components whose detected key size is below the ECCG recommendation for quantum-sensitive contexts:

```text
actualKeyBits < 192
```

The rule is intended to flag agreed block ciphers that may be acceptable in general contexts but should be avoided when resistance to quantum attacks is required. In practice, this means that AES-128 can be reported because its detected parameter size is below the 192-bit threshold.

For example, the following pyca/cryptography code can produce a CBOM entry for AES-CBC with a detected parameter size of 128 bits:

```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"K" * 16
iv = b"I" * 16

cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
)
```

The same rule may also fire for other AES-128 modes, such as AES-ECB:

```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"K" * 16

cipher = Cipher(
    algorithms.AES(key),
    modes.ECB(),
)
```

However, detecting key sizes through the CBOM is not guaranteed to be reliable. The parameterSetIdentifier field may represent the key size for some algorithms, such as AES-128, but it may represent a different parameter for others. For example, some block cipher entries may expose a block size, mode-related value, or algorithm identifier rather than the actual secret key length.

## ECCG-HASH-001: SHA-224 Legacy Hash Function

**Severity: critical**

ECCG-HASH-001 detects use of SHA-224 as a hash primitive. Under this rule set, SHA-224 is treated as legacy-only and is not included in the agreed hash function list.

The rule is triggered when a CBOM component is identified as both:

```rego
is_hash_primitive(component)
is_sha224(component)
```

For example, the following pyca/cryptography code can produce a CBOM entry for SHA-224:

```py
from cryptography.hazmat.primitives import hashes, hmac

mac = hmac.HMAC(
    key=b"K" * 32,
    algorithm=hashes.SHA224(),
)

mac.update(b"message using SHA-224")
tag = mac.finalize()
```

This rule is marked as critical because SHA-224 is classified as legacy-only in the policy and should not be used as an agreed hash function.

## ECCG-HASH-002: SHA-512/224 Legacy Hash Function

**Severity: critical**

ECCG-HASH-002 detects use of SHA-512/224 as a hash primitive. Under this rule set, SHA-512/224 is also treated as legacy-only and is not included in the agreed hash function list.

The rule is triggered when a CBOM component is identified as both:

```
is_hash_primitive(component)
is_sha512_224(component)
```

For example, the following pyca/cryptography code can produce a CBOM entry for SHA-512/224:

```py
from cryptography.hazmat.primitives import hashes, hmac

mac = hmac.HMAC(
    key=b"K" * 32,
    algorithm=hashes.SHA512_224(),
)

mac.update(b"message using SHA-512/224")
tag = mac.finalize()
```

This rule is marked as critical because SHA-512/224 is classified as legacy-only in the policy and should not be used as an agreed hash function.

## ECCG-HASH-005: Obsolete SHA-1 Hash Function

**Severity: critical**

ECCG-HASH-005 detects use of SHA-1 as a hash primitive. Under this policy set, SHA-1 is treated as obsolete and is not included in the agreed hash function list.

The rule is triggered when a CBOM component is identified as both:

```rego
is_hash_primitive(component)
is_sha1(component)
```

For example, the following pyca/cryptography code can produce a CBOM entry for SHA-1:

```py
from cryptography.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SHA1())
digest.update(b"message using SHA-1")
result = digest.finalize()
```

SHA-1 should not be used for new cryptographic designs. If SHA-1 appears as a standalone hash primitive, it should be replaced with an agreed hash function such as SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, or SHA3-512, depending on the security requirements.

If SHA-1 appears as the underlying hash for HMAC-SHA1, the HMAC construction may also produce a separate MAC-related finding. In that case, the SHA-1 finding identifies the obsolete underlying hash primitive, while the HMAC finding identifies the legacy MAC construction.

# Symmetric Constructions 

## ECCG-SYM-ENC-001: Non-Agreed Symmetric Encryption Scheme

**Severity: Critical**

ECCG-SYM-ENC-001 detects symmetric encryption schemes that are not in the agreed ECCG symmetric encryption scheme list. The agreed list currently includes:

```text
CTR
OFB
CBC
CBC-CS
CFB
```

Any detected symmetric encryption scheme outside that list is reported as non-compliant. For example, AES-ECB is detected as a symmetric encryption scheme, but ECB is not included in the agreed scheme list.

For example, the following pyca/cryptography code can produce a CBOM entry for AES-ECB:

```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"K" * 16

cipher = Cipher(
    algorithms.AES(key),
    modes.ECB(),
)
```

## ECCG-HMAC-002: Legacy HMAC-SHA1

**Severity: high and critical after 2030**

ECCG-HMAC-002 detects HMAC-SHA1. Under this policy set, HMAC-SHA1 is considered acceptable only as a legacy mechanism and should be phased out.

The rule is triggered when a CBOM component is identified as a MAC primitive using HMAC with SHA-1.

For example, the following pyca/cryptography code can produce a CBOM entry for HMAC-SHA1:

```py
from cryptography.hazmat.primitives import hashes, hmac

mac = hmac.HMAC(
    key=b"K" * 32,
    algorithm=hashes.SHA1(),
)

mac.update(b"message using HMAC-SHA1")
tag = mac.finalize()
```

The rule reports this as a high-severity finding because SHA-1-based HMAC is legacy-bound in the implemented policy. Although HMAC-SHA1 is not the same as plain SHA-1 hashing, new designs should use stronger HMAC variants such as HMAC-SHA256, HMAC-SHA384, or HMAC-SHA512 where appropriate.

## ECCG-AE-005: Ambiguous Encryption and MAC Composition

**Severity: medium**

ECCG-AE-005 detects cases where a symmetric encryption component and a MAC component appear in a common source context. This may indicate a manually composed authenticated-encryption construction.

The rule is intended to catch code patterns that may correspond to one of the following schemes:

```
Encrypt-then-MAC
MAC-then-Encrypt
Encrypt-and-MAC
```

Under the ECCG guidance represented by this policy set, Encrypt-then-MAC is treated as agreed, while MAC-then-Encrypt and Encrypt-and-MAC are treated as legacy. However, the CBOM does not expose enough data-flow or ordering information to reliably distinguish these constructions.

For example, the following pyca/cryptography code can produce both an AES-CBC component and an HMAC-SHA256 component in the same source file:

```py
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

aes_key = b"A" * 16
hmac_key = b"H" * 32
iv = b"I" * 16

plaintext = b"message"

padder = padding.PKCS7(128).padder()
padded = padder.update(plaintext) + padder.finalize()

cipher = Cipher(
    algorithms.AES(aes_key),
    modes.CBC(iv),
)

encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded) + encryptor.finalize()

mac = hmac.HMAC(
    hmac_key,
    hashes.SHA256(),
)

mac.update(ciphertext)
tag = mac.finalize()
```

This rule is deliberately heuristic. It can detect that encryption and MAC operations occur together, but it cannot prove whether the MAC is computed over the plaintext or the ciphertext. Because of that, the finding requires manual review.

# Asymmetric Atomic Primitives 

## ECCG-RSA-002: Legacy RSA Modulus Size

**Severity: critical**

ECCG-RSA-002 detects RSA primitives whose modulus size is in the ECCG legacy range:

```
1900 <= modulusBits < 3000
```

In practice, this means RSA-2048 is flagged as legacy. RSA security depends heavily on the size of the modulus n. Under this rule set, RSA keys below 3000 bits are treated as legacy. A 2048-bit RSA key is still commonly encountered, but it does not meet the recommended ECCG modulus-size threshold. The rule reports this as a critical finding because the detected RSA primitive is classified as Legacy[2025].

The ECCG rule also includes a condition on the RSA public exponent:

```
log2(e) > 16
```

However, CycloneDX does not expose the RSA public exponent in the CBOM data used by this rule. Because of that, the policy can only evaluate the modulus size. The finding therefore marks the exponent check as:

```
not_verifiable
```
