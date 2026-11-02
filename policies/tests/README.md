# Policy tests

Run from the repository root:

```bash
docker compose run --rm --no-deps opa-local test /policies
```

With OPA installed locally, use `opa test policies/eccg`. The Docker service
pins the project's OPA version. To select one section, add
`--run 'section_tests.block_ciphers'`, replacing `block_ciphers` with the suite
name below. Parameterized test output names the failing case.

## Parameterized tests

`test_cyclonedx_cases[test_case.name]` defines a separate named test case for each
fixture. The name in square brackets is a key in the rule's result object.
The section suites use the following rule:

```rego
test_cyclonedx_cases[test_case.name] if {
    some test_case in cases
    actual_findings := findings
        with input as test_case.input
        with time.now_ns as test_case.evaluationTime
    test_helpers.matches(test_case, actual_findings)
}
```

- `some test_case in cases` selects each fixture from the `cases` array.
- `[test_case.name]` identifies the result using that fixture's name.
- The `with` clauses supply its CBOM and evaluation time to the policy.
- `matches` checks the actual findings against that fixture's expectations.

Each successful case contributes a `true` value under its name. For three
passing AES cases, the result has this form:

```json
{
  "AES 128 bits": true,
  "AES 192 bits": true,
  "AES 256 bits": true
}
```

`opa test` evaluates the named cases individually and reports `PASS` or `FAIL`
for each one. Case names should be unique within a suite. To see the block cipher
case results, run from the repository root:

```bash
docker compose run --rm --no-deps opa-local test /policies \
    --run 'section_tests.block_ciphers.test_cyclonedx_cases$' --verbose
```

Excerpt from a successful run, with timing omitted:

```text
data.cbom.eccg.section_tests.block_ciphers.test_cyclonedx_cases: PASS
  ...
  AES 128 bits: PASS
  AES 192 bits: PASS
  AES 256 bits: PASS
  ...
```

Keep the case name in the rule head. A plain Boolean rule using
`some test_case in cases` can succeed when just one case passes. The parameterized
form checks each named case and identifies which one failed.
See [OPA's parameterized test documentation](https://www.openpolicyagent.org/docs/policy-testing#parameterized-tests-and-data-driven-testing).

## Section coverage

The `*_cyclonedx_test.rego` files are beside their policy implementations.
Each suite checks an exact set of findings, including rule IDs, severity,
component identity, and source references. Active sections also check their
findings through `data.cbom.eccg.findings`, including section metadata.

| Policy section | Suite name | Additional cases |
| --- | --- | --- |
| Block ciphers | `block_ciphers` | AES sizes, quantum threshold, 3DES size and 2027 cutoff |
| Hashes | `hashes` | Agreed hashes, OIDs, 384-bit threshold |
| XOFs | `xofs` | SHAKE/cSHAKE, OIDs, 256-bit threshold |
| AES modes | `aes_modes` | Conditional modes, ECB rejection, IV and GCM notes |
| Authenticated encryption | `authenticated_encryption` | GCM, CCM, EAX, rejection and component attribution |
| MACs | `macs` | HMAC/KMAC, CBC-MAC, GMAC, 2030 cutoff, occurrence-window boundaries |
| Disk encryption | `disk_encryption` | XTS, CBC-ESSIV, stream-cipher and context warnings |
| Key combiners | `key_combiners` | Declared combiners, dependency graphs, same-file evidence |
| Key derivation | `key_derivation` | Agreed KDFs, PBKDF2 PRF note, unknown KDFs |
| Key protection | `key_protection` | AES-KW/KWP, SIV, wrapping OIDs, context warnings |
| Password protection | `password_protection` | PBKDF2, Argon2id, parameter advisories, KDF context |
| RSA | `rsa` | 3000-bit boundary, missing/invalid modulus strings, OIDs and families |
| EC-DLOG | `ec_dlog` | Registered and legacy curve fields, CBOMkit ECDH/ECDSA regressions, NIST note, parameter precedence, missing curves |
| FF-DLOG | `ff_dlog` | MODP/FFDHE, 3072-bit boundary, IKE group identifiers, unknown sizes |
| Asymmetric encryption | `asymmetric_encryption` | OAEP/PKCS#1 notes, rejection, OID/family/name precedence |
| Digital signatures | `digital_signatures` | Agreed schemes, rejected schemes, identifier precedence |
| Key establishment / KEM | `key_establishment` | Classical schemes, ML-KEM/FrodoKEM parameter sets and OIDs |
| DRBG | `drbg` | Agreed generators, critical rejection, all four note advisories |
| General key material | `key_material` | Private/public keys and nested CycloneDX material properties |

Key-material policies are tested directly; they remain excluded from the main
assessment. The integration suite checks this exclusion and verifies that every
active policy source has a section suite. Existing focused helper and malformed
input tests remain alongside these suites.

## Helper type contracts

Test helper definitions include `Args`, `Returns`, and, where needed, `Locals`
comments so each variable's type is visible beside the function. The shared
[helper module](../eccg/cyclonedx_test_helpers.rego) defines the object shapes for
components, CBOMs, test cases, findings, and source references.

`array<T>` means an ordered collection; `set<T>` means an unordered collection of
unique values; `object<string, any>` means an object with string keys and arbitrary
values. Section findings are sets, while the main assessment returns an array.
Expected findings are arrays of partial finding objects. The `matches` predicate
returns `true` on success and is undefined when an assertion fails.

Helpers enforce these contracts with executable guards such as `is_string`,
`is_array`, and the shared predicates in
[test_type_helpers.rego](../eccg/test_type_helpers.rego). Invalid argument types
make the helper undefined, so a positive fixture assertion cannot succeed.
The guards check component and test-case shapes, nested source occurrences,
finding fields, and collection element types before matching or projecting them.
Full CycloneDX schema and enum validation still uses the separate validator below.

Focused unit-test helpers explicitly allow arbitrary JSON values in fields used
to exercise malformed input. Their component/property containers still require
objects with string keys; these partial records remain separate from complete
CycloneDX fixtures. Helper contract regressions run with the normal suite; select
them alone with `--run 'test_type_helpers_test'`.

## CycloneDX fixtures

[cyclonedx_test_helpers.rego](../eccg/cyclonedx_test_helpers.rego) builds complete
[CycloneDX 1.7](https://cyclonedx.org/docs/1.7/json/) documents. In particular:

- BOMs include `bomFormat`, `specVersion`, `version`, and `components`.
- Crypto components use `type: "cryptographic-asset"` and a `bom-ref`.
- Primitive, family, mode, and parameter-set fields are nested under
  `cryptoProperties.algorithmProperties`; algorithm parameter sets are strings.
- OIDs are under `cryptoProperties.oid`. Key-material properties are under
  `cryptoProperties.relatedCryptoMaterialProperties`; material sizes are integers.
- Curve fixtures cover both `algorithmProperties.ellipticCurve` and the older
  `algorithmProperties.curve`. A usable `ellipticCurve` value takes precedence.
- Evidence uses `evidence.occurrences`; relationships use root `dependencies`
  with `ref` and `dependsOn` references.

Valid fixture documents use the schema's algorithm-family, curve, and mode
values. Unknown parameter strings can still be valid CycloneDX and are tested
as insufficient policy evidence. Malformed-type and flattened-field tests are
separate unit tests, not part of the valid-document export.

Tests mock `time.now_ns` for deterministic legacy cutoffs. They do not add the
nonstandard `policyEvaluationDate` property to CycloneDX documents. Note-based
advisories are tested as advisories; the fixtures do not claim to prove seed
entropy, nonce uniqueness, or other runtime properties absent from the CBOM.

## Validate fixtures against the official schemas

Prepare a separate Python environment and download the official schemas once:

```bash
python3 -m venv /tmp/eccg-test-venv
/tmp/eccg-test-venv/bin/python -m pip install -r policies/tests/requirements.txt
mkdir -p /tmp/eccg-schemas
for schema in bom-1.7.schema.json cryptography-defs.schema.json spdx.schema.json jsf-0.82.schema.json; do
    curl --fail --silent --show-error --location \
        "https://cyclonedx.org/schema/$schema" --output "/tmp/eccg-schemas/$schema"
done
```

Export the same documents used by the Rego tests and validate them:

```bash
docker compose run --rm --no-deps opa-local eval --data /policies --format raw \
    data.cbom.eccg.cyclonedx_integration_test.fixture_documents > /tmp/eccg-fixtures.json
/tmp/eccg-test-venv/bin/python policies/tests/validate_cyclonedx_fixtures.py \
    --schema-dir /tmp/eccg-schemas /tmp/eccg-fixtures.json
```

Validation resolves schema references locally and checks that every implemented
rule ID has a positive fixture. The export contains each BOM under `bom`, with
its suite, case name, and expected findings alongside it; only `bom` is the
CycloneDX input. To add coverage, add a named case and explicit expected findings
to the corresponding section suite; the export includes it automatically.
