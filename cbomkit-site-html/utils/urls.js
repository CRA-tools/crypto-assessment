/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modified for CRA Compliance Checker.
 */

/**
 * Normalizes the repository URL format expected by the CBOMkit scan API.
 *
 * CBOMkit can accept package-style URLs such as `pkg:*`, so those are left
 * unchanged. For regular Git URLs, this removes CBOMkit-style SCM prefixes,
 * removes a trailing `.git`, and adds `https://` when the user entered a
 * shorthand value such as `github.com/org/repo`.
 */
export function normalizeScanUrl(value) {
  let scanUrl = value.trim();

  if (!scanUrl.startsWith("pkg:")) {
    scanUrl = scanUrl.replace(/^scm:git:git:\/\//, "").replace(/\.git$/, "");

    if (!scanUrl.includes("://")) {
      scanUrl = `https://${scanUrl}`;
    }
  }

  return scanUrl;
}

/**
 * Normalizes the repository URL format expected by the Semgrep scan service.
 *
 * Semgrep needs a cloneable Git URL, so package URLs such as `pkg:*` are
 * rejected. For regular Git URLs, this removes CBOMkit-style SCM prefixes and
 * adds `https://` when the user entered a shorthand value such as
 * `github.com/org/repo`.
 */
export function normalizeGitUrlForSemgrep(value) {
  let gitUrl = value.trim();

  if (gitUrl.startsWith("pkg:")) {
    throw new Error(
      "Semgrep needs a cloneable Git URL, for example https://github.com/org/repo."
    );
  }

  gitUrl = gitUrl.replace(/^scm:git:git:\/\//, "");

  if (!gitUrl.includes("://")) {
    gitUrl = `https://${gitUrl}`;
  }

  return gitUrl;
}

/**
 * Builds the request body sent to the CBOMkit scan endpoint.
 *
 * The scan URL is normalized for CBOMkit first. Optional branch, subfolder, and
 * PAT values are only added when provided, so blank fields are not sent to the
 * backend.
 *
 * @param {object} form Repository scan fields.
 * @param {string} form.url Git or package URL to scan.
 * @param {string} [form.branch] Optional Git branch.
 * @param {string} [form.scanPath] Optional repository subfolder.
 * @param {string} [form.pat] Optional personal access token.
 * @returns {{scanUrl: string, branch?: string, subfolder?: string,
 *   credentials?: {pat: string}}} A CBOMkit-compatible scan request.
 */
export function buildCbomScanRequest({ url, branch, scanPath, pat }) {
  const request = { scanUrl: normalizeScanUrl(url) };

  if (branch?.trim()) {
    request.branch = branch.trim();
  }

  if (scanPath?.trim()) {
    request.subfolder = scanPath.trim();
  }

  if (pat?.trim()) {
    request.credentials = {
      pat: pat.trim(),
    };
  }

  return request;
}

/**
 * Builds the request body sent to the local Semgrep scan service.
 *
 * The Git URL is normalized into a cloneable repository URL. Optional branch,
 * commit, subfolder, and PAT values are included only when present. This allows
 * the same UI form to support full-repository scans, subfolder scans, branch
 * scans, and exact commit scans.
 */
export function buildSemgrepScanRequest({ url, branch, commit, scanPath, pat }) {
  const request = {
    gitUrl: normalizeGitUrlForSemgrep(url),
  };

  if (branch.trim()) {
    request.branch = branch.trim();
  }

  if (commit.trim()) {
    request.commit = commit.trim();
  }

  if (scanPath.trim()) {
    request.subfolder = scanPath.trim();
  }

  if (pat.trim()) {
    request.credentials = {
      pat: pat.trim(),
    };
  }

  return request;
}

/**
 * Checks whether a returned CBOM record belongs to the scan URL currently being
 * polled.
 *
 * CBOMkit may expose the repository URL either as `record.gitUrl` or inside the
 * CBOM metadata properties as `gitUrl`. This helper checks both locations so the
 * polling logic can reliably find the CBOM generated for the current request.
 */
export function recordMatchesScanUrl(record, scanUrl) {
  if (record.gitUrl === scanUrl) return true;

  return record.bom?.metadata?.properties?.some(
    (property) => property.name === "gitUrl" && property.value === scanUrl
  );
}
