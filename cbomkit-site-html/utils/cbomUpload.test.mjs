/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { readCbomFile } from "./cbomUpload.js";

const validCbom = { bomFormat: "CycloneDX", specVersion: "1.6", components: [] };
const file = (contents, name = "cbom.json") => ({
  name,
  text: async () => contents,
});

test("accepts the repository's existing CBOM examples", async () => {
  for (const name of [
    "cbom.json",
    "cboms/asymmetric-atomic-primitives.json",
    "cboms/symmetric-atomic-primitives.json",
    "cboms/symmetric-atomic-primitives-2.json",
    "cboms/symmetric-constructions.json",
  ]) {
    const contents = await readFile(new URL(`../../${name}`, import.meta.url), "utf8");
    assert.deepEqual(await readCbomFile(file(contents)), JSON.parse(contents));
  }
});

test("accepts an empty component inventory and a UTF-8 BOM", async () => {
  assert.deepEqual(
    await readCbomFile(file(`\uFEFF${JSON.stringify(validCbom)}`, "CBOM.JSON")),
    validCbom
  );
});

test("rejects unrelated JSON and malformed CBOM structures", async () => {
  for (const value of [
    null, false, 42, "cbom", [], {}, { hello: "world" },
    { ...validCbom, bomFormat: "SPDX" },
    { ...validCbom, specVersion: null },
    { ...validCbom, specVersion: "" },
    { ...validCbom, components: {} },
  ]) {
    await assert.rejects(readCbomFile(file(JSON.stringify(value))), /CycloneDX CBOM/);
  }
});

test("rejects malformed components and missing cryptographic properties", async () => {
  for (const component of [
    null, [], {}, { type: "library" },
    { type: "cryptographic-asset", name: "AES" },
    { type: "cryptographic-asset", name: "AES", cryptoProperties: {} },
  ]) {
    await assert.rejects(
      readCbomFile(file(JSON.stringify({ ...validCbom, components: [component] }))),
      /invalid component/
    );
  }
});

test("reports invalid extensions, JSON syntax, and unreadable files", async () => {
  await assert.rejects(readCbomFile(file("{}", "cbom.txt")), /\.json extension/);
  await assert.rejects(readCbomFile(file("{ broken")), /not valid JSON/);
  await assert.rejects(readCbomFile(file("")), /not valid JSON/);
  await assert.rejects(
    readCbomFile({ name: "cbom.json", text: async () => { throw new Error("unreadable"); } }),
    /Could not read/
  );
});
