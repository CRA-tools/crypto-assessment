/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 */

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

export async function readCbomFile(file) {
  if (!file.name.toLowerCase().endsWith(".json")) {
    throw new Error("Select a CBOM file with a .json extension.");
  }

  let text;
  try {
    text = await file.text();
  } catch {
    throw new Error(
      "Could not read the selected CBOM file. Select it again and retry."
    );
  }

  let cbom;
  try {
    cbom = JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch {
    throw new Error("The selected file is not valid JSON.");
  }

  // Check the structure consumed by the policy service before sending input.
  if (
    !isObject(cbom) ||
    cbom.bomFormat !== "CycloneDX" ||
    typeof cbom.specVersion !== "string" ||
    !/^\d+\.\d+$/.test(cbom.specVersion) ||
    !Array.isArray(cbom.components)
  ) {
    throw new Error(
      "Select a CycloneDX CBOM with bomFormat, specVersion, and a components array."
    );
  }

  for (const component of cbom.components) {
    if (
      !isObject(component) ||
      !isNonEmptyString(component.type) ||
      !isNonEmptyString(component.name) ||
      (component.type === "cryptographic-asset" &&
        (!isObject(component.cryptoProperties) ||
          !isNonEmptyString(component.cryptoProperties.assetType)))
    ) {
      throw new Error(
        "The CBOM contains an invalid component. Each component needs a type and name; cryptographic assets also need cryptoProperties.assetType."
      );
    }
  }

  return cbom;
}
