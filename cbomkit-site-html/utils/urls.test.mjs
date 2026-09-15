/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from "node:assert/strict";
import test from "node:test";

import { buildCbomScanRequest } from "./urls.js";

test("CBOM scan omits subfolder when no path is provided", () => {
  assert.deepEqual(
    buildCbomScanRequest({
      url: "https://github.com/example/project.git",
    }),
    {
      scanUrl: "https://github.com/example/project",
    }
  );
});

test("CBOM scan treats a whitespace-only path as a whole-repository scan", () => {
  assert.deepEqual(
    buildCbomScanRequest({
      url: "https://github.com/example/project",
      scanPath: "   ",
      pat: "   ",
    }),
    {
      scanUrl: "https://github.com/example/project",
    }
  );
});

test("CBOM scan forwards a selected path to the analyzer", () => {
  assert.deepEqual(
    buildCbomScanRequest({
      url: "github.com/example/project",
      branch: " release ",
      scanPath: " packages/api ",
      pat: " secret-token ",
    }),
    {
      scanUrl: "https://github.com/example/project",
      branch: "release",
      subfolder: "packages/api",
      credentials: {
        pat: "secret-token",
      },
    }
  );
});
