# Demo code for CBOMkit assessments

The Python files in [code](code) contain pyca/cryptography snippets for scanning
with CBOMkit. Each example has a comment identifying the rule it should trigger,
or should not trigger, when the analyzer supplies the required evidence.

The files contain function definitions rather than a demo runner. CBOMkit scans
the source; calling the functions or running Python is not required. The snippets
include agreed algorithms, deliberately non-agreed uses, and an invalid AES
constructor to exercise different assessment outcomes.

## Scan the examples

1. Open the assessment frontend, normally at `http://localhost:8000`.
2. Enter `https://github.com/CRA-tools/crypto-assessment.git`, or the URL of a fork
   containing the examples.
3. Select the branch containing the changes and set **Scan path** to `demo/code`.
4. Press **Check compliance**, then **Show findings** to inspect the results and
   source references.

The repository scan reads the selected remote branch. Local, uncommitted edits
are not included in that workflow. The optional commit SHA applies to Semgrep;
CBOMkit scans the selected branch. See the [main usage guide](../README.md#usage).

## Reading the results

The comments describe expected policy behavior, conditional on the generated
CycloneDX CBOM. Detection depends on the analyzer's support for the API call and
the primitive, identifiers, parameters, and source occurrences it records.
A missing finding can mean that the analyzer missed or incompletely described
an operation. It does not establish that the example passed the policy.

One operation can produce findings in several sections. For example, an ECDSA
signature can use an agreed signature scheme while its curve produces a separate
EC-DLOG finding. Agreed schemes can also produce operational advisories.

| Severity | Meaning in these examples |
| --- | --- |
| `critical` | A scheme or parameter is rejected, or a rule assigns this severity to legacy use. |
| `high` | Used by the invalid/missing AES-size rule and private-key material detection. |
| `medium` | Quantum-sensitive recommendations or ambiguous password/key-protection context. |
| `low` | Disk-encryption context heuristics that can produce false positives. |
| `warning` | An implementation requirement, uncertain metadata, or a composition requiring review. |
| `info` | Public-key material detection. |
| `error` | The current legacy-status helper's severity after a legacy period expires. |

## Snippets by section

The tables map the current rules to the source examples. They include expected
non-findings and limitations; they do not claim that every rule can be triggered
by scanning a supported PyCA API.

### Symmetric atomic primitives

| Section and source | Rules and expected behavior |
| --- | --- |
| [Block ciphers](code/symmetric_atomic_primitives_block_ciphers.py) | `ECCG-BLOCK-001`: rejects block ciphers outside the current AES allowlist, including Blowfish, SM4, and 3DES. `ECCG-BLOCK-002`: reports AES sizes outside 128/192/256 bits, including missing size evidence. `ECCG-BLOCK-003`: reports legacy 3DES use. `ECCG-BLOCK-004`: additionally reports a detected 3DES size other than 168 bits. `ECCG-BLOCK-005`: reports agreed ciphers below the 192-bit threshold. |
| [Hashes](code/symmetric_atomic_primitives_hashes.py) | `ECCG-HASH-001`: rejects non-agreed hashes, including SHA-224, SHA-512/224, and BLAKE2b. `ECCG-HASH-002`: reports agreed hashes below the 384-bit threshold. SHA-256 exercises the latter; correctly identified SHA-384 should trigger neither rule. |
| [XOFs](code/xofs.py) | `ECCG-XOF-001`: rejects non-agreed XOFs; the supplied SHAKE examples are agreed. `ECCG-XOF-002`: compares the recorded parameter value with 256 bits. The short-output examples exercise that condition only if the analyzer records a value below 256. |

`invalid_aes_key_size()` deliberately passes a 160-bit key. PyCA rejects that
constructor if the function is called. It is an invalid-usage source example,
not an executable AES construction with a nonstandard key size.

The 3DES legacy marker is `L[2027]`. The current policies assign
`ECCG-BLOCK-003` and `ECCG-BLOCK-004` severity `critical` through 2027 and `error`
afterwards. `ECCG-BLOCK-001` can also report 3DES independently.

### Symmetric constructions

| Section and source | Rules and expected behavior |
| --- | --- |
| [AES modes](code/symmetric_constructions_aes_modes.py) | `ECCG-SYM-ENC-001`: rejects ECB and other unagreed constructions. `ECCG-SYM-ENC-002`: requests integrity protection for conditionally agreed modes. `ECCG-SYM-ENC-003`: requests IV/nonce review for those modes. |
| [GCM and authenticated encryption](code/symmetric_constructions_authenticated_encryption.py) | `ECCG-SYM-ENC-004`, `ECCG-SYM-ENC-005`, and `ECCG-SYM-ENC-006`: GCM IV construction, plaintext-length, and full-tag advisories. `ECCG-SEAS-001`: rejects ChaCha20-Poly1305 under the current AE allowlist. `ECCG-SEAS-002`: requests challenge/nonce review for agreed GCM/CCM. |
| [MACs](code/symmetric_constructions_mac_block_ciphers.py) | `ECCG-MAC-001`: rejects a non-agreed MAC such as Poly1305 if classified as `mac`; it also emits a separate warning for nearby encryption/MAC occurrences. `ECCG-MAC-002`: requests tag-truncation review. `ECCG-HMAC-001`: supplies the HMAC/KMAC quantum-security advisory. |
| [CBC-MAC and GMAC](code/symmetric_constructions_mac_block_ciphers.py) | `ECCG-CBC-MAC-001`: fixed-input-length advisory. `ECCG-GMAC-001`, `ECCG-GMAC-002`, and `ECCG-GMAC-003`: nonce management, IV configuration, and full-tag advisories. These require the analyzer to identify the MAC construction, not only AES-CBC or AES-GCM. |
| [Disk encryption](code/symmetric_constructions_disk_encryption.py) | `ECCG-DISK-001`: ordinary CBC exercises the non-agreed disk-scheme heuristic. `ECCG-DISK-002`: ChaCha20 exercises the stream-cipher heuristic. `ECCG-DISK-003`: XTS tweak advisories. `ECCG-DISK-004`: CBC-ESSIV sector-number and malleability advisories, if the full construction is recognized. |
| [Key combiners](code/symmetric_constructions_key_combiners.py) | `ECCG-KC-001`: two distinct key-establishment assets and a KDF in the same file can produce a composition warning. The examples combine ECDH/X25519 or X25519/ML-KEM secrets using HKDF. |
| [Key derivation](code/symmetric_constructions_key_derivation.py) | `ECCG-KDF-001`: rejects unrecognized or non-agreed KDF schemes; correctly recognized HKDF and X9.63 should pass. Concatenation-KDF recognition depends on its emitted identifiers. `ECCG-KDF-002`: PBKDF2 PRF advisory, exercised in the [password examples](code/symmetric_constructions_password_protection.py). |
| [Key protection](code/symmetric_constructions_key_protection.py) | `ECCG-KP-001`: medium review finding for schemes outside the recognized KW/KWP/SIV list. Correctly classified KW/KWP/SIV examples should pass; GCM can produce this finding because AE metadata alone does not establish key-protection context. |
| [Password protection](code/symmetric_constructions_password_protection.py) | `ECCG-PWH-001`: medium review finding for scrypt and other KDFs outside the password-scheme list. `ECCG-PWH-002`: PBKDF2 salt/iteration advisory. `ECCG-PWH-003`: Argon2id parameter advisory. The Argon2id snippet uses 64 MiB, below the policy's stated 2 GiB recommendation. |

HMAC-SHA1 is accepted as legacy through 2030 by the current MAC helpers. It can
receive `ECCG-MAC-002` and `ECCG-HMAC-001` advisories during that period;
afterwards it is rejected by `ECCG-MAC-001`. Its underlying SHA-1 hash can also
produce an independent `ECCG-HASH-001` finding.

The MAC-then-Encrypt and Encrypt-and-MAC examples are in the authenticated
encryption file. The composition branch of `ECCG-MAC-001` uses a 15-line
source-occurrence window. It requests review and cannot prove the ordering of
encryption and authentication from source proximity alone.

PBKDF2 and scrypt can be assessed by both the KDF and password sections. Generic
HKDF usage can also receive `ECCG-PWH-001`: the current classification uses the
`kdf` primitive and cannot establish whether the application hashes passwords.

### Asymmetric atomic primitives

| Section and source | Rules and expected behavior |
| --- | --- |
| [RSA](code/assymetric_atomic_primitives_rsa.py) | `ECCG-RSA-001`: critical for known positive moduli below 3000 bits. The 1024-bit and 2048-bit examples should trigger it; 3072 bits should not. Missing or unusable modulus metadata produces no RSA-size finding. |
| [EC-DLOG](code/asymmetric_atomic_primitives_ec_dlog.py) | `ECCG-ECDLOG-001`: critical for an identified curve outside the allowlist, such as secp256k1; warning if the curve cannot be determined. `ECCG-ECDLOG-002`: advisory for agreed NIST curves such as P-256. |
| [FF-DLOG](code/asymmetric_atomic_primitives_ff_dlog.py) | `ECCG-FFDLOG-001`: rejects a DH domain that cannot be identified as an agreed group. `ECCG-FFDLOG-002`: rejects an identified agreed group below 3072 bits, or warns when its size is unresolved. Named ffdhe2048 and ffdhe3072 provide rejection and acceptance examples when their group identities survive extraction. |

### Asymmetric constructions

| Section and source | Rules and expected behavior |
| --- | --- |
| [Asymmetric encryption](code/asymmetric_constructions_encryption.py) | `ECCG-AS-ENC-001`: rejects unagreed or unidentified encryption schemes. Both supplied schemes are agreed. `ECCG-AS-ENC-002`: random-padding advisory. `ECCG-AS-ENC-003`: PKCS#1 v1.5 padding-attack advisory. `ECCG-AS-ENC-004`: OAEP decoding/padding advisory. `ECCG-AS-ENC-005`: quantum-threat advisory for both schemes. |
| [Digital signatures](code/asymmetric_constructions_digital_signatures.py) | `ECCG-DG-001`: rejects signature schemes outside the agreed list. RSA-PSS, RSA-PKCS1, ECDSA, deterministic ECDSA, DSA, Ed25519, Ed448, and ML-DSA are expected non-findings for this rule. Atomic-primitive findings remain independent. |
| [Key establishment and encapsulation](code/asymmetric_constructions_key_establishment.py) | `ECCG-KEE-001`: rejects unagreed schemes; the supplied ECDH, X25519/X448, and ML-KEM examples are agreed. `ECCG-KEE-002`: authentication advisory. `ECCG-KEE-003`: ML-KEM parameter recommendation; identified 768/1024 sets should not trigger it. `ECCG-KEE-004`: FrodoKEM parameter recommendation; no native PyCA example is available here. |

### Random number generation and key material

| Section and source | Rules and expected behavior |
| --- | --- |
| [Random number generation](code/random_number_generation.py) | `ECCG-DRBG-001`: rejection of unagreed DRBGs. `ECCG-DRBG-002`, `ECCG-DRBG-003`, and `ECCG-DRBG-004`: seeding, quantum-entropy, and backtracking-resistance advisories. `ECCG-DRBG-005`: CTR_DRBG cipher-key-size advisory. The supplied `os.urandom` example identifies none of these constructions and should trigger none of these rules. |
| [Key serialization](code/general_key_material.py) and [embedded keys](code/hardcoded_keys.py) | `ECCG-RSA-KEY-001`: private-key material, severity `high`. `ECCG-RSA-KEY-002`: public-key material, severity `info`. These rules exist in the General section, which is currently excluded from the main assessment. RSA operations using these keys can still produce findings in active sections. |

[cbom_crypto_demo.py](code/cbom_crypto_demo.py) provides compact AES-GCM,
HMAC-SHA256, and ECDH/HKDF examples. It contains no CBOM generator or policy
evaluation code.

## Detection and API limitations

- **DRBGs:** PyCA exposes no public HMAC_DRBG, Hash_DRBG, or CTR_DRBG constructor
  for these snippets. OS randomness, key generation, or individual HMAC/hash/AES
  calls do not establish a particular DRBG. The DRBG rules have no positive
  source example in this directory.
- **Unavailable rejection cases:** the supplied native PyCA XOF, signature,
  RSA-encryption, and key-establishment APIs implement agreed schemes. Their
  acceptance examples do not demonstrate the corresponding rejection branches.
  PyCA 50's ML-KEM API exposes 768/1024 rather than 512, and no FrodoKEM API is
  used here. Missing parameter evidence can still produce an ML-KEM advisory.
- **Composed constructions:** CBC-MAC, GMAC, and CBC-ESSIV are assembled from
  PyCA primitives. Detection of their building blocks does not guarantee that
  CBOMkit emits the construction name or the primitive required by its rule.
- **Parameters and identifiers:** `parameterSetIdentifier` may describe a key
  size, block size, output size, or strength, depending on the detected asset.
  Inspect the generated component before interpreting a size finding. Curve
  identity, padding, and named DH groups can also be lost or merged during
  extraction.
- **API support:** ML-KEM, ML-DSA, Argon2id, and imports from
  `cryptography.hazmat.decrepit` require matching analyzer support. A valid Python
  call can be absent from the resulting CBOM.
- **Operational requirements:** advisory rules do not prove nonce uniqueness,
  tag truncation, password parameters, peer authentication, or seed entropy.
  Disk, key-protection, password, and combiner context can require manual review.

The [policy README](../policies/README.MD) documents the rules. The executable
definitions under [policies/eccg](../policies/eccg) determine the actual findings.
