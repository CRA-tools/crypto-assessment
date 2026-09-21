/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static frontend independently implemented for CRA Compliance Checker.
 */

import { getOpaEndpoint, getSemgrepEndpoint } from "./config/endpoints.js";

import { buildSemgrepScanRequest } from "./utils/urls.js";

import { generateCbom } from "./api/cbomApi.js";

import {
  extractImportantFindings,
  groupRegoFindings,
} from "./utils/regoFindings.js";

import {
  getSemgrepFindings,
  groupSemgrepFindingsBySection,
} from "./utils/semgrepFindings.js";

const elements = {
  darkModeToggle: document.getElementById("darkModeToggle"),
  form: document.getElementById("complianceForm"),
  repoUrl: document.getElementById("repoUrl"),
  scanPath: document.getElementById("scanPath"),
  branch: document.getElementById("branch"),
  commit: document.getElementById("commit"),
  pat: document.getElementById("pat"),
  checkButton: document.getElementById("checkButton"),
  status: document.getElementById("status"),
  errorBox: document.getElementById("errorBox"),
  results: document.getElementById("results"),
  complianceBanner: document.getElementById("complianceBanner"),
  summary: document.getElementById("summary"),
  toggleFindingsButton: document.getElementById("toggleFindingsButton"),
  findingsContainer: document.getElementById("findingsContainer"),
  regoResults: document.getElementById("regoResults"),
  semgrepResults: document.getElementById("semgrepResults"),
  downloadCbomButton: document.getElementById("downloadCbomButton"),
};

let abortController = null;
let latestCbom = null;

function getInitialTheme() {
  const savedTheme = window.localStorage.getItem("cra-compliance-theme");

  if (savedTheme === "dark") return true;
  if (savedTheme === "light") return false;

  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

function applyTheme(isDark) {
  document.documentElement.dataset.theme = isDark ? "dark" : "light";

  if (elements.darkModeToggle) {
    elements.darkModeToggle.checked = isDark;
  }

  window.localStorage.setItem("cra-compliance-theme", isDark ? "dark" : "light");
}

function setStatus(message) {
  elements.status.textContent = `Status: ${message}`;
}

function showError(message) {
  elements.errorBox.hidden = false;
  elements.errorBox.textContent = message;
}

function clearError() {
  elements.errorBox.hidden = true;
  elements.errorBox.textContent = "";
}

function setCbomDownloadAvailable(isAvailable) {
  if (!elements.downloadCbomButton) return;

  elements.downloadCbomButton.hidden = !isAvailable;
  elements.downloadCbomButton.disabled = !isAvailable;
  elements.downloadCbomButton.style.display = isAvailable ? "inline-flex" : "none";
}

function clearResults() {
  latestCbom = null;
  setCbomDownloadAvailable(false);

  elements.results.hidden = true;
  elements.complianceBanner.innerHTML = "";
  elements.summary.innerHTML = "";
  elements.regoResults.innerHTML = "";
  elements.semgrepResults.innerHTML = "";
  elements.findingsContainer.hidden = true;
  elements.toggleFindingsButton.textContent = "Show findings";
}

function setBusy(isBusy) {
  elements.checkButton.disabled = isBusy;
  elements.checkButton.textContent = isBusy ? "Checking..." : "Check compliance";
}

function makeErrorMessage(error) {
  if (!error) return "Unknown error.";

  if (error instanceof DOMException && error.name === "AbortError") {
    return "The compliance check was cancelled.";
  }

  if (error instanceof Error) return error.message;

  return String(error);
}

function formatOpaErrors(body, responseText) {
  if (Array.isArray(body?.errors)) {
    return body.errors
      .map((error) => {
        const location = error.location
          ? `${error.location.file || "policy"}:${error.location.row || "?"}:${
              error.location.col || "?"
            }`
          : "";

        return [error.message, error.code, location].filter(Boolean).join(" | ");
      })
      .join("\n");
  }

  if (body?.message) return body.message;
  if (body?.error) return body.error;
  if (responseText) return responseText;

  return "";
}

async function evaluateRegoPolicy({ cbom, signal }) {
  if (!cbom) {
    throw new Error("No CBOM is available to evaluate.");
  }

  setStatus("Evaluating REGO policy...");

  const response = await fetch(getOpaEndpoint(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      input: cbom,
    }),
    signal,
  });

  const responseText = await response.text();

  let body = null;

  try {
    body = responseText ? JSON.parse(responseText) : null;
  } catch {
    body = null;
  }

  if (!response.ok) {
    const details = formatOpaErrors(body, responseText);

    throw new Error(
      details || `OPA policy evaluation failed with HTTP ${response.status}.`
    );
  }

  return body;
}

async function runSemgrep({ form, signal }) {
  setStatus("Running Semgrep evaluation...");

  const response = await fetch(getSemgrepEndpoint(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(buildSemgrepScanRequest(form)),
    signal,
  });

  const body = await response.json().catch(() => null);

  if (!response.ok || body?.ok === false) {
    throw new Error(
      body?.error || `Semgrep scan failed with HTTP ${response.status}.`
    );
  }

  return body;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function normalizeSeverity(severity) {
  return String(severity || "").trim().toLowerCase();
}

function isBlockingSeverity(severity) {
  const normalized = normalizeSeverity(severity);
  return ["critical", "error", "high"].includes(normalized);
}

function getSeverityClass(severity) {
  const normalized = normalizeSeverity(severity);

  if (["critical", "error", "high"].includes(normalized)) {
    return "badge badge--danger";
  }

  if (normalized === "medium") {
    return "badge badge--warning";
  }

  if (normalized === "warning") {
    return "badge badge--notice";
  }

  return "badge badge--ok";
}

function countSeverities(findings) {
  const counts = {
    critical: 0,
    error: 0,
    high: 0,
    medium: 0,
    warning: 0,
    low: 0,
    other: 0,
  };

  for (const finding of findings) {
    const severity = normalizeSeverity(finding.severity);

    if (severity === "critical") {
      counts.critical += 1;
    } else if (severity === "error") {
      counts.error += 1;
    } else if (severity === "high") {
      counts.high += 1;
    } else if (severity === "medium") {
      counts.medium += 1;
    } else if (severity === "warning") {
      counts.warning += 1;
    } else if (severity === "low") {
      counts.low += 1;
    } else {
      counts.other += 1;
    }
  }

  return counts;
}

function renderSeverityPills(counts) {
  const wrapper = document.createElement("div");
  wrapper.className = "severity-pills";

  const pills = [
    ["critical", counts.critical],
    ["error", counts.error],
    ["high", counts.high],
    ["medium", counts.medium],
    ["warning", counts.warning],
    ["low", counts.low],
    ["other", counts.other],
  ];

  for (const [severity, count] of pills) {
    if (count === 0) continue;

    const pill = document.createElement("span");
    pill.className = `severity-pill severity-pill--${severity}`;
    pill.textContent = `${count} ${severity}`;
    wrapper.appendChild(pill);
  }

  return wrapper;
}

function formatReference(reference) {
  const location = reference.location || reference.path || "Unknown file";
  const line = reference.line ? `:${reference.line}` : "";
  const column = reference.column ? `:${reference.column}` : "";

  return `${location}${line}${column}`;
}

function renderComplianceBanner({ allFindings }) {
  const counts = countSeverities(allFindings);
  const blockingCount = counts.critical + counts.error + counts.high;
  const compliant = blockingCount === 0;

  const className = compliant
    ? "compliance-banner compliance-banner--pass"
    : "compliance-banner compliance-banner--fail";

  const title = compliant ? "Compliant" : "Not compliant";

  const message = compliant
    ? "No critical, error, or high findings were detected."
    : `${blockingCount} blocking finding${
        blockingCount === 1 ? "" : "s"
      } detected. Critical, error, and high findings make the code non-compliant.`;

  elements.complianceBanner.innerHTML = `
    <div class="${className}">
      <strong>${escapeHtml(title)}</strong>
      <span>${escapeHtml(message)}</span>
    </div>
  `;
}

function renderSummary({ regoFindings, semgrepFindings }) {
  const allFindings = [...regoFindings, ...semgrepFindings];
  const counts = countSeverities(allFindings);
  const blockingCount = counts.critical + counts.error + counts.high;

  elements.summary.innerHTML = `
    <div class="summary-card">
      <strong>${escapeHtml(allFindings.length)}</strong>
      <span>Total findings</span>
    </div>
    <div class="summary-card">
      <strong>${escapeHtml(blockingCount)}</strong>
      <span>Blocking findings</span>
    </div>
    <div class="summary-card">
      <strong>${escapeHtml(regoFindings.length)}</strong>
      <span>REGO findings</span>
    </div>
    <div class="summary-card">
      <strong>${escapeHtml(semgrepFindings.length)}</strong>
      <span>Semgrep findings</span>
    </div>
  `;
}

function renderGroupedFindings(container, title, groups) {
  container.innerHTML = "";

  const section = document.createElement("section");
  section.className = "finding-panel";

  const headingRow = document.createElement("div");
  headingRow.className = "finding-panel__header";

  const heading = document.createElement("h3");
  heading.textContent = title;
  headingRow.appendChild(heading);

  const total = groups.reduce((sum, group) => sum + group.findings.length, 0);

  const totalBadge = document.createElement("span");
  totalBadge.className = "finding-panel__total";
  totalBadge.textContent = `${total} finding${total === 1 ? "" : "s"}`;
  headingRow.appendChild(totalBadge);

  section.appendChild(headingRow);

  if (!groups.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No findings returned.";
    section.appendChild(empty);
    container.appendChild(section);
    return;
  }

  const groupList = document.createElement("div");
  groupList.className = "finding-group-list";

  for (const group of groups) {
    const counts = countSeverities(group.findings);

    const details = document.createElement("details");
    details.className = "finding-accordion";

    const summary = document.createElement("summary");
    summary.className = "finding-accordion__summary";

    const left = document.createElement("div");
    left.className = "finding-accordion__left";

    const groupTitle = document.createElement("strong");
    groupTitle.className = "finding-accordion__title";
    groupTitle.textContent = group.title;
    left.appendChild(groupTitle);

    const meta = document.createElement("span");
    meta.className = "finding-accordion__meta";
    meta.textContent = `${group.findings.length} finding${
      group.findings.length === 1 ? "" : "s"
    }`;
    left.appendChild(meta);

    const right = document.createElement("div");
    right.className = "finding-accordion__right";
    right.appendChild(renderSeverityPills(counts));

    summary.appendChild(left);
    summary.appendChild(right);
    details.appendChild(summary);

    const cards = document.createElement("div");
    cards.className = "finding-card-list";

    for (const finding of group.findings) {
      const card = document.createElement("article");
      card.className = "finding-card";

      const cardHeader = document.createElement("div");
      cardHeader.className = "finding-card__header";

      const findingTitle = document.createElement("strong");
      findingTitle.className = "finding-card__title";
      findingTitle.textContent = finding.title || finding.ruleId || "Finding";
      cardHeader.appendChild(findingTitle);

      if (finding.severity) {
        const badge = document.createElement("span");
        badge.className = getSeverityClass(finding.severity);
        badge.textContent = normalizeSeverity(finding.severity).toUpperCase();
        cardHeader.appendChild(badge);
      }

      card.appendChild(cardHeader);

      const metaItems = [];

      if (finding.ruleId) {
        metaItems.push(`Rule: ${finding.ruleId}`);
      }

      if (finding.location) {
        metaItems.push(`Location: ${finding.location}`);
      }

      if (metaItems.length > 0) {
        const cardMeta = document.createElement("div");
        cardMeta.className = "finding-card__meta";
        cardMeta.textContent = metaItems.join(" · ");
        card.appendChild(cardMeta);
      }

      if (finding.message) {
        const message = document.createElement("p");
        message.className = "finding-card__message";
        message.textContent = finding.message;
        card.appendChild(message);
      }

      if (Array.isArray(finding.references) && finding.references.length > 0) {
        const references = document.createElement("details");
        references.className = "finding-card__references";

        const referencesSummary = document.createElement("summary");
        referencesSummary.textContent = `${finding.references.length} reference${
          finding.references.length === 1 ? "" : "s"
        }`;
        references.appendChild(referencesSummary);

        const referencesList = document.createElement("ul");

        for (const reference of finding.references) {
          const referenceItem = document.createElement("li");
          referenceItem.textContent = formatReference(reference);
          referencesList.appendChild(referenceItem);
        }

        references.appendChild(referencesList);
        card.appendChild(references);
      }

      cards.appendChild(card);
    }

    details.appendChild(cards);
    groupList.appendChild(details);
  }

  section.appendChild(groupList);
  container.appendChild(section);
}

function renderResults({ policyResult, semgrepResult }) {
  const regoFindings = extractImportantFindings(policyResult);
  const groupedRegoFindings = groupRegoFindings(regoFindings);

  const semgrepFindings = getSemgrepFindings(semgrepResult);
  const groupedSemgrepFindings =
    groupSemgrepFindingsBySection(semgrepFindings);

  const allFindings = [...regoFindings, ...semgrepFindings];

  elements.results.hidden = false;
  elements.findingsContainer.hidden = true;
  elements.toggleFindingsButton.textContent = "Show findings";

  renderComplianceBanner({ allFindings });

  renderSummary({
    regoFindings,
    semgrepFindings,
  });

  renderGroupedFindings(
    elements.regoResults,
    "REGO findings",
    groupedRegoFindings
  );

  renderGroupedFindings(
    elements.semgrepResults,
    "Semgrep findings",
    groupedSemgrepFindings
  );

  setCbomDownloadAvailable(Boolean(latestCbom));
}

function getFormValues() {
  return {
    url: elements.repoUrl.value.trim(),
    scanPath: elements.scanPath.value.trim(),
    branch: elements.branch.value.trim(),
    commit: elements.commit.value.trim(),
    pat: elements.pat.value.trim(),
  };
}

function getCbomDownloadFileName() {
  const repositoryName =
    elements.repoUrl.value
      .trim()
      .replace(/\.git$/, "")
      .split("/")
      .filter(Boolean)
      .pop() || "repository";

  const timestamp = new Date()
    .toISOString()
    .replaceAll(":", "-")
    .replace(/\.\d{3}Z$/, "Z");

  return `${repositoryName}-cbom-${timestamp}.json`;
}

function downloadLatestCbom() {
  if (!latestCbom) {
    showError("No generated CBOM is available to download.");
    return;
  }

  const blob = new Blob([JSON.stringify(latestCbom, null, 2)], {
    type: "application/json",
  });

  const downloadUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = downloadUrl;
  link.download = getCbomDownloadFileName();

  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(downloadUrl);
}

async function handleComplianceCheck(event) {
  event.preventDefault();

  clearError();
  clearResults();

  const form = getFormValues();

  if (!form.url) {
    showError("Enter a Git URL first.");
    return;
  }

  abortController?.abort();
  abortController = new AbortController();

  setBusy(true);

  try {
    const cbom = await generateCbom({
      ...form,
      signal: abortController.signal,
      onStatus: setStatus,
    });

    latestCbom = cbom;

    const policyResult = await evaluateRegoPolicy({
      cbom,
      signal: abortController.signal,
    });

    const semgrepResult = await runSemgrep({
      form,
      signal: abortController.signal,
    });

    renderResults({
      policyResult,
      semgrepResult,
    });

    const regoFindings = extractImportantFindings(policyResult);
    const semgrepFindings = getSemgrepFindings(semgrepResult);
    const allFindings = [...regoFindings, ...semgrepFindings];
    const blockingCount = allFindings.filter((finding) =>
      isBlockingSeverity(finding.severity)
    ).length;

    setStatus(
      blockingCount > 0
        ? "Compliance check finished: not compliant"
        : "Compliance check finished: compliant"
    );
  } catch (error) {
    setStatus("Compliance check failed");
    showError(makeErrorMessage(error));
  } finally {
    abortController = null;
    setBusy(false);
  }
}

function toggleFindings() {
  const shouldShow = elements.findingsContainer.hidden;

  elements.findingsContainer.hidden = !shouldShow;
  elements.toggleFindingsButton.textContent = shouldShow
    ? "Hide findings"
    : "Show findings";
}

elements.darkModeToggle.addEventListener("change", (event) => {
  applyTheme(event.target.checked);
});

elements.form.addEventListener("submit", handleComplianceCheck);
elements.toggleFindingsButton.addEventListener("click", toggleFindings);

elements.downloadCbomButton.addEventListener("click", downloadLatestCbom);

applyTheme(getInitialTheme());
