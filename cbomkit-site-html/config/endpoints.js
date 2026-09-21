/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modified for CRA Compliance Checker.
 */

const runtimeConfig = globalThis.window?.CRA_COMPLIANCE_CONFIG ?? {};
const pageLocation = globalThis.window?.location;

// The services run on the same host as the frontend by default, including on VMs.
function defaultApiBase(port) {
  const protocol = pageLocation?.protocol === "https:" ? "https:" : "http:";
  const hostname = pageLocation?.hostname || "localhost";
  return `${protocol}//${hostname}:${port}`;
}

export const HTTP_API_BASE =
  runtimeConfig.CBOMKIT_HTTP_API_BASE || defaultApiBase(8081);

export const WS_API_BASE =
  runtimeConfig.CBOMKIT_WS_API_BASE ||
  HTTP_API_BASE.replace(/^http:/, "ws:").replace(/^https:/, "wss:");

export const SEMGREP_API_BASE =
  runtimeConfig.SEMGREP_API_BASE || defaultApiBase(9091);

export const POLICY_API_BASE =
  runtimeConfig.POLICY_API_BASE || defaultApiBase(8182);

export const OPA_DECISION_PATH =
  runtimeConfig.OPA_DECISION_PATH || "/v1/data/cbom/eccg";

export function getCbomScanEndpoint(clientId) {
  return `${WS_API_BASE.replace(/\/$/, "")}/v1/scan/${encodeURIComponent(
    clientId
  )}`;
}

export function getOpaEndpoint() {
  const base = POLICY_API_BASE.replace(/\/$/, "");
  const path = OPA_DECISION_PATH.startsWith("/")
    ? OPA_DECISION_PATH
    : `/${OPA_DECISION_PATH}`;

  return `${base}${path}`;
}

export function getSemgrepEndpoint() {
  return `${SEMGREP_API_BASE.replace(/\/$/, "")}/scan`;
}
