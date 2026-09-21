/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static frontend independently implemented for CRA Compliance Checker.
 */

import { getCbomScanEndpoint } from "../config/endpoints.js";
import { buildCbomScanRequest } from "../utils/urls.js";

const SCAN_TIMEOUT_MS = 30 * 60 * 1000;

const SCAN_INPUT_GUIDANCE =
  "Check the repository URL, branch, scan path, and PAT permissions. If those inputs are correct, review the CBOMkit backend logs for more details.";

function getErrorDetails(error) {
  if (error instanceof Error) return error.message.trim();
  if (typeof error === "string") return error.trim();
  if (typeof error?.message === "string") return error.message.trim();
  if (typeof error?.error === "string") return error.error.trim();

  return "";
}

function asSentence(value) {
  return /[.!?]$/.test(value) ? value : `${value}.`;
}

function getProjectDirectory(label) {
  const value = String(label || "").trim();
  const foundModule = value.match(/^Found project module '([^']+)'/i);

  if (foundModule) return foundModule[1].trim();

  const scanningProject = value.match(
    /^Scanning\s+\S+\s+project\s+(.+?)\s+\(\d+\/\d+\)$/i
  );

  return scanningProject?.[1]?.trim() || "";
}

function getBackendErrorLocation(update, scanDirectory) {
  const message = update?.message;
  const location =
    (message && typeof message === "object" ? message.location : null) ||
    update?.location;
  const locationObject =
    location && typeof location === "object" ? location : null;
  const file = [
    typeof location === "string" ? location : "",
    locationObject?.file,
    locationObject?.path,
    message?.file,
    message?.path,
    message?.filename,
    update?.file,
    update?.path,
    update?.filename,
  ].find((value) => typeof value === "string" && value.trim());

  if (file) {
    const line =
      locationObject?.line ??
      locationObject?.row ??
      message?.line ??
      update?.line;
    const column =
      locationObject?.column ??
      locationObject?.col ??
      message?.column ??
      update?.column;
    const position = [line, column]
      .filter((value) => Number.isInteger(value) && value > 0)
      .join(":");

    return ` Source file: ${file.trim()}${position ? `:${position}` : ""}.`;
  }

  return scanDirectory
    ? ` Scan directory: ${scanDirectory}. The backend did not identify the exact source file.`
    : "";
}

function createClientId() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }

  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function parseCbom(message) {
  if (typeof message === "string") {
    return JSON.parse(message);
  }

  if (message && typeof message === "object") {
    return message;
  }

  throw new Error("CBOMkit returned an invalid CBOM payload.");
}

/**
 * Runs a CBOMkit scan over its WebSocket API.
 *
 * Unlike the REST endpoint, the WebSocket reports terminal backend errors and
 * returns the generated CBOM directly. This prevents parser and clone failures
 * from being misreported as polling timeouts.
 */
export function scanCbomOverWebSocket({
  scanRequest,
  signal,
  onStatus = () => {},
  timeoutMs = SCAN_TIMEOUT_MS,
  clientId = createClientId(),
  WebSocketImpl = globalThis.WebSocket,
}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("The operation was aborted.", "AbortError"));
      return;
    }

    if (!WebSocketImpl) {
      reject(new Error("This browser does not support WebSocket scans."));
      return;
    }

    let socket;
    let cbom = null;
    let lastStatus = "";
    let scanDirectory = "";
    let settled = false;

    const timeoutId = setTimeout(() => {
      settle(
        reject,
        new Error(
          "CBOMkit did not finish the scan within 30 minutes. Check the backend logs for a stalled analyzer."
        )
      );
    }, timeoutMs);

    function cleanup() {
      clearTimeout(timeoutId);
      signal?.removeEventListener("abort", handleAbort);

      if (socket) {
        socket.removeEventListener("open", handleOpen);
        socket.removeEventListener("message", handleMessage);
        socket.removeEventListener("error", handleError);
        socket.removeEventListener("close", handleClose);

        if (
          socket.readyState === WebSocketImpl.OPEN ||
          socket.readyState === WebSocketImpl.CONNECTING
        ) {
          socket.close();
        }
      }
    }

    function settle(callback, value) {
      if (settled) return;

      settled = true;
      cleanup();
      callback(value);
    }

    function handleAbort() {
      settle(
        reject,
        new DOMException("The operation was aborted.", "AbortError")
      );
    }

    function reportStatus(status) {
      if (status === lastStatus) return;

      lastStatus = status;
      onStatus(status);
    }

    function handleOpen() {
      reportStatus("Connected to CBOMkit. Starting scan...");
      socket.send(JSON.stringify(scanRequest));
    }

    function handleMessage(event) {
      let update;

      try {
        update = JSON.parse(String(event.data).trim());
      } catch {
        settle(reject, new Error("CBOMkit returned an invalid scan update."));
        return;
      }

      const type = String(update?.type || "").toUpperCase();
      const message = update?.message;

      if (type === "ERROR") {
        const backendDetails = getErrorDetails(message);
        const details = backendDetails
          ? ` The backend reported: ${asSentence(backendDetails)}`
          : " The backend did not provide a specific reason.";
        const location = getBackendErrorLocation(update, scanDirectory);

        settle(
          reject,
          new Error(
            `CBOMkit could not complete the scan.${details}${location} ${SCAN_INPUT_GUIDANCE}`
          )
        );
        return;
      }

      if (type === "WARNING") {
        reportStatus(`CBOMkit warning: ${message || "Unknown warning."}`);
        return;
      }

      if (type === "CBOM") {
        try {
          cbom = parseCbom(message);
        } catch (error) {
          settle(reject, error);
        }
        return;
      }

      if (type === "LABEL") {
        const label = String(message || "").trim();
        const projectDirectory = getProjectDirectory(label);

        if (projectDirectory) {
          scanDirectory = projectDirectory;
        }

        if (label === "Finished") {
          if (!cbom) {
            settle(
              reject,
              new Error("CBOMkit finished without returning a generated CBOM.")
            );
            return;
          }

          settle(resolve, cbom);
          return;
        }

        if (label) {
          reportStatus(`CBOMkit: ${label}`);
        }
      }
    }

    function handleError(event) {
      const browserDetails = getErrorDetails(event?.error || event?.message);
      const details = browserDetails
        ? ` The browser reported: ${browserDetails}`
        : "";

      settle(
        reject,
        new Error(
          `Could not connect to the CBOMkit scan service.${details} Confirm that the CBOMkit backend is running and reachable. Also check that the WebSocket URL uses wss:// when this page is served over HTTPS and that the backend allows this frontend origin.`
        )
      );
    }

    function handleClose(event) {
      const reason = event?.reason?.trim()
        ? ` The server reported: ${event.reason.trim()}`
        : " The server did not provide a reason.";
      const code = Number.isInteger(event?.code)
        ? ` (WebSocket close code ${event.code})`
        : "";

      settle(
        reject,
        new Error(
          `CBOMkit closed the scan connection before the CBOM was ready${code}.${reason} Confirm that the backend is still running, then review its logs for a failed or interrupted scan.`
        )
      );
    }

    signal?.addEventListener("abort", handleAbort, { once: true });

    try {
      socket = new WebSocketImpl(getCbomScanEndpoint(clientId));
      socket.addEventListener("open", handleOpen);
      socket.addEventListener("message", handleMessage);
      socket.addEventListener("error", handleError);
      socket.addEventListener("close", handleClose);
    } catch (error) {
      const browserDetails = getErrorDetails(error);
      const details = browserDetails
        ? ` The browser reported: ${browserDetails}`
        : "";

      settle(
        reject,
        new Error(
          `Could not start the CBOMkit WebSocket connection.${details} Check that the configured WebSocket URL is valid and uses ws:// for HTTP pages or wss:// for HTTPS pages.`
        )
      );
    }
  });
}

export function generateCbom({ signal, onStatus, ...form }) {
  const scanRequest = buildCbomScanRequest(form);

  onStatus?.("Connecting to CBOMkit...");

  return scanCbomOverWebSocket({
    scanRequest,
    signal,
    onStatus,
  });
}
