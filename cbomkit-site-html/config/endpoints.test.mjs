/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from "node:assert/strict";
import test from "node:test";

let moduleId = 0;

async function loadEndpoints(pageUrl, config = {}) {
  const previousWindow = globalThis.window;
  globalThis.window = {
    location: new URL(pageUrl),
    CRA_COMPLIANCE_CONFIG: config,
  };
  try {
    return await import(`./endpoints.js?test=${++moduleId}`);
  } finally {
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  }
}

for (const [pageUrl, httpBase, wsBase] of [
  ["http://localhost:8000/", "http://localhost", "ws://localhost"],
  ["http://192.168.122.251:8000/", "http://192.168.122.251", "ws://192.168.122.251"],
  ["https://checker.example:8443/", "https://checker.example", "wss://checker.example"],
  ["http://[::1]:8000/", "http://[::1]", "ws://[::1]"],
]) {
  test(`service requests use the frontend host at ${pageUrl}`, async () => {
    const endpoints = await loadEndpoints(pageUrl);

    assert.equal(endpoints.HTTP_API_BASE, `${httpBase}:8081`);
    assert.equal(
      endpoints.getCbomScanEndpoint("scan/client"),
      `${wsBase}:8081/v1/scan/scan%2Fclient`
    );
    assert.equal(endpoints.getOpaEndpoint(), `${httpBase}:8182/v1/data/cbom/eccg`);
    assert.equal(endpoints.getSemgrepEndpoint(), `${httpBase}:9091/scan`);
  });
}

test("explicit service URLs override the frontend host", async () => {
  const endpoints = await loadEndpoints("http://192.168.122.251:8000/", {
    CBOMKIT_HTTP_API_BASE: "https://api.example/cbom",
    CBOMKIT_WS_API_BASE: "wss://stream.example/cbom/",
    POLICY_API_BASE: "https://api.example/policy/",
    OPA_DECISION_PATH: "v1/data/custom",
    SEMGREP_API_BASE: "https://api.example/semgrep/",
  });

  assert.equal(endpoints.HTTP_API_BASE, "https://api.example/cbom");
  assert.equal(endpoints.getCbomScanEndpoint("client"), "wss://stream.example/cbom/v1/scan/client");
  assert.equal(endpoints.getOpaEndpoint(), "https://api.example/policy/v1/data/custom");
  assert.equal(endpoints.getSemgrepEndpoint(), "https://api.example/semgrep/scan");
});

test("the WebSocket URL follows an explicit HTTP service URL", async () => {
  const endpoints = await loadEndpoints("http://192.168.122.251:8000/", {
    CBOMKIT_HTTP_API_BASE: "https://api.example/cbom/",
  });

  assert.equal(endpoints.getCbomScanEndpoint("client"), "wss://api.example/cbom/v1/scan/client");
});
