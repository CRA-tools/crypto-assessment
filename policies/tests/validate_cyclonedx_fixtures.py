"""Validate exported policy fixtures against the official CycloneDX schemas.

The schema directory must contain bom-1.7.schema.json and its referenced
cryptography-defs.schema.json, spdx.schema.json, and jsf-0.82.schema.json.
All schema references resolve locally; validation does not access the network.
"""

import argparse
import json
from pathlib import Path
import re

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource


SCHEMA_FILENAMES = (
    "bom-1.7.schema.json",
    "cryptography-defs.schema.json",
    "spdx.schema.json",
    "jsf-0.82.schema.json",
)
POLICY_DIRECTORY = Path(__file__).resolve().parents[1] / "eccg"


# Validate the exported BOMs and require a positive fixture for every implemented rule
# ID. Validation failures include the suite, case, and JSON path, and terminate the
# command with a nonzero exit status.
def main():
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("fixtures", type=Path, help="JSON exported from fixture_documents.")
    argument_parser.add_argument("--schema-dir", type=Path, required=True)
    arguments = argument_parser.parse_args()

    # Register both URL schemes used by schema references. All resources come from local
    # files, so validation is reproducible without network retrieval.
    schema_registry = Registry()
    schemas_by_filename = {}
    for schema_filename in SCHEMA_FILENAMES:
        schema_path = arguments.schema_dir / schema_filename
        if not schema_path.is_file():
            argument_parser.error(f"Missing official schema: {schema_path}")
        schema_document = json.loads(schema_path.read_text(encoding="utf-8"))
        schemas_by_filename[schema_filename] = schema_document
        schema_resource = Resource.from_contents(schema_document)
        for url_scheme in ("http", "https"):
            schema_registry = schema_registry.with_resource(
                f"{url_scheme}://cyclonedx.org/schema/{schema_filename}", schema_resource
            )

    bom_validator = Draft7Validator(
        schemas_by_filename[SCHEMA_FILENAMES[0]],
        registry=schema_registry,
        format_checker=FormatChecker(),
    )
    fixture_documents = json.loads(arguments.fixtures.read_text(encoding="utf-8"))
    if not isinstance(fixture_documents, list) or not fixture_documents:
        argument_parser.error("Expected a nonempty array of exported fixture documents.")

    # Validate only the nested bom document. The surrounding expected findings and case
    # labels are test metadata, not CycloneDX root properties.
    validation_failures = []
    covered_rule_ids = set()
    for fixture_document in fixture_documents:
        fixture_label = f'{fixture_document["suite"]} / {fixture_document["case"]}'
        for validation_error in bom_validator.iter_errors(fixture_document["bom"]):
            json_path = "/".join(str(path_segment) for path_segment in validation_error.absolute_path)
            validation_failures.append(f"{fixture_label}: {json_path}: {validation_error.message}")
        covered_rule_ids.update(
            expected_finding["ruleId"] for expected_finding in fixture_document["expected"]
        )

    # Scan production Rego for implemented IDs, excluding test expectations. This detects
    # rules that were added without a positive fixture; OPA tests separately verify that the
    # expected findings actually occur.
    implemented_rule_ids = set()
    for policy_path in POLICY_DIRECTORY.rglob("*.rego"):
        if policy_path.name.endswith("_test.rego") or policy_path.name == "cyclonedx_test_helpers.rego":
            continue
        implemented_rule_ids.update(re.findall(r'"(ECCG-[A-Z0-9-]+-\d{3})"', policy_path.read_text()))
    uncovered_rule_ids = implemented_rule_ids - covered_rule_ids
    if uncovered_rule_ids:
        validation_failures.append(f"Rules without a positive fixture: {', '.join(sorted(uncovered_rule_ids))}")
    # Report all document and coverage failures together so one validation run identifies
    # every fixture that needs attention.
    if validation_failures:
        raise SystemExit("\n".join(validation_failures))
    print(
        f"Validated {len(fixture_documents)} CycloneDX 1.7 fixtures; "
        f"all {len(implemented_rule_ids)} rule IDs are exercised."
    )


if __name__ == "__main__":
    main()
