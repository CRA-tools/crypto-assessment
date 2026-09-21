/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from "node:assert/strict";
import test from "node:test";

import { scanCbomOverWebSocket } from "./cbomApi.js";

class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 3;
  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = FakeWebSocket.CONNECTING;
    this.listeners = new Map();
    this.sent = [];
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  removeEventListener(type, listener) {
    if (this.listeners.get(type) === listener) {
      this.listeners.delete(type);
    }
  }

  send(message) {
    this.sent.push(message);
  }

  close() {
    this.readyState = FakeWebSocket.CLOSED;
  }

  emit(type, event = {}) {
    if (type === "open") {
      this.readyState = FakeWebSocket.OPEN;
    }

    this.listeners.get(type)?.(event);
  }
}

function startScan(overrides = {}) {
  FakeWebSocket.instances = [];

  const promise = scanCbomOverWebSocket({
    scanRequest: {
      scanUrl: "https://github.com/example/project",
    },
    clientId: "scan-client",
    WebSocketImpl: FakeWebSocket,
    ...overrides,
  });

  return {
    promise,
    socket: FakeWebSocket.instances[0],
  };
}

test("WebSocket scan sends the request and resolves the streamed CBOM", async () => {
  const statuses = [];
  const expectedCbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
  };
  const { promise, socket } = startScan({
    onStatus: (status) => statuses.push(status),
  });

  assert.equal(socket.url, "ws://localhost:8081/v1/scan/scan-client");

  socket.emit("open");
  assert.deepEqual(JSON.parse(socket.sent[0]), {
    scanUrl: "https://github.com/example/project",
  });

  socket.emit("message", {
    data: JSON.stringify({ type: "LABEL", message: "Scanning..." }),
  });
  socket.emit("message", {
    data: JSON.stringify({ type: "LABEL", message: "Scanning..." }),
  });
  socket.emit("message", {
    data: JSON.stringify({
      type: "CBOM",
      message: JSON.stringify(expectedCbom),
    }),
  });
  socket.emit("message", {
    data: JSON.stringify({ type: "LABEL", message: "Finished" }),
  });

  assert.deepEqual(await promise, expectedCbom);
  assert.deepEqual(statuses, [
    "Connected to CBOMkit. Starting scan...",
    "CBOMkit: Scanning...",
  ]);
  assert.equal(socket.readyState, FakeWebSocket.CLOSED);
});

test("WebSocket scan rejects a backend error without waiting for a timeout", async () => {
  const { promise, socket } = startScan();

  socket.emit("open");
  socket.emit("message", {
    data: JSON.stringify({
      type: "ERROR",
      message: "Parse error at line 18 column 25",
    }),
  });

  await assert.rejects(
    promise,
    (error) => {
      assert.match(error.message, /CBOMkit could not complete the scan/);
      assert.match(
        error.message,
        /The backend reported: Parse error at line 18 column 25/
      );
      assert.match(error.message, /Check the repository URL, branch, scan path/);
      return true;
    }
  );
  assert.equal(socket.readyState, FakeWebSocket.CLOSED);
});

test("WebSocket scan includes the project directory reported before an error", async () => {
  const { promise, socket } = startScan();

  socket.emit("open");
  socket.emit("message", {
    data: JSON.stringify({
      type: "LABEL",
      message:
        "Found project module 'insighioNode/apps/demo_console/templ' [19 .py files]",
    }),
  });
  socket.emit("message", {
    data: JSON.stringify({
      type: "ERROR",
      message: "Parse error at line 18 column 25",
    }),
  });

  await assert.rejects(promise, (error) => {
    assert.match(
      error.message,
      /Scan directory: insighioNode\/apps\/demo_console\/templ\./
    );
    assert.match(error.message, /did not identify the exact source file/);
    return true;
  });
});

test("WebSocket scan displays a structured source file location when provided", async () => {
  const { promise, socket } = startScan();

  socket.emit("open");
  socket.emit("message", {
    data: JSON.stringify({
      type: "ERROR",
      message: {
        message: "Parse error",
        location: {
          file: "src/config.py",
          line: 18,
          column: 25,
        },
      },
    }),
  });

  await assert.rejects(promise, (error) => {
    assert.match(error.message, /Source file: src\/config\.py:18:25\./);
    return true;
  });
});

test("WebSocket scan explains connection failures and suggests checks", async () => {
  const { promise, socket } = startScan();

  socket.emit("error", {
    error: new Error("Connection refused"),
  });

  await assert.rejects(promise, (error) => {
    assert.match(error.message, /Could not connect to the CBOMkit scan service/);
    assert.match(error.message, /The browser reported: Connection refused/);
    assert.match(error.message, /backend is running and reachable/);
    assert.match(error.message, /wss:\/\//);
    assert.match(error.message, /allows this frontend origin/);
    return true;
  });
  assert.equal(socket.readyState, FakeWebSocket.CLOSED);
});

test("WebSocket scan explains an unexpected close", async () => {
  const { promise, socket } = startScan();

  socket.emit("open");
  socket.emit("close", {
    code: 1011,
    reason: "Analyzer stopped",
  });

  await assert.rejects(promise, (error) => {
    assert.match(error.message, /before the CBOM was ready/);
    assert.match(error.message, /WebSocket close code 1011/);
    assert.match(error.message, /The server reported: Analyzer stopped/);
    assert.match(error.message, /review its logs/);
    return true;
  });
});

test("WebSocket scan explains setup errors instead of exposing only the exception", async () => {
  class ThrowingWebSocket {
    constructor() {
      throw new SyntaxError("The URL is invalid");
    }
  }

  const promise = scanCbomOverWebSocket({
    scanRequest: { scanUrl: "https://github.com/example/project" },
    clientId: "scan-client",
    WebSocketImpl: ThrowingWebSocket,
  });

  await assert.rejects(promise, (error) => {
    assert.match(error.message, /Could not start the CBOMkit WebSocket connection/);
    assert.match(error.message, /The browser reported: The URL is invalid/);
    assert.match(error.message, /configured WebSocket URL is valid/);
    return true;
  });
});

test("WebSocket scan closes and rejects when it is aborted", async () => {
  const controller = new AbortController();
  const { promise, socket } = startScan({ signal: controller.signal });

  controller.abort();

  await assert.rejects(
    promise,
    (error) => error instanceof DOMException && error.name === "AbortError"
  );
  assert.equal(socket.readyState, FakeWebSocket.CLOSED);
});
