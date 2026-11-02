/*
 * Copyright 2026 ExcID
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("./index.html", import.meta.url), "utf8");
const cbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [{
    type: "cryptographic-asset",
    name: "AES",
    cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "block-cipher" } },
  }],
};
const makeFile = (contents = JSON.stringify(cbom), name = "uploaded.json") => ({
  name,
  text: async () => contents,
});
const response = (body, ok = true) => ({
  ok,
  status: ok ? 200 : 500,
  text: async () => JSON.stringify(body),
  json: async () => body,
});
const policyResponse = (findings = []) => response({ result: { findings } });
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

class Element {
  value = "";
  disabled = false;
  hidden = true;
  style = {};
  dataset = {};
  files = [];
  children = [];
  listeners = {};
  textContent = "";
  innerHTML = "";
  addEventListener(type, listener) { this.listeners[type] = listener; }
  appendChild(child) { this.children.push(child); }
  click() { return this.listeners.click?.({ target: this }); }
  remove() {}
}

let moduleId = 0;
async function loadApp(t, fetchImpl = async () => policyResponse()) {
  const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)]
    .map(([, id]) => [id, new Element()]));
  const requests = [];
  const sockets = [];
  const downloads = [];
  class FakeWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    constructor() { this.readyState = 0; this.listeners = {}; sockets.push(this); }
    addEventListener(type, listener) { this.listeners[type] = listener; }
    removeEventListener(type) { delete this.listeners[type]; }
    send() {}
    close() { this.readyState = 3; }
    emit(type, event = {}) {
      if (type === "open") this.readyState = 1;
      this.listeners[type]?.(event);
    }
  }
  const document = {
    getElementById: id => elements[id],
    createElement: () => new Element(),
    documentElement: new Element(),
    body: new Element(),
  };
  const globals = {
    document,
    window: { localStorage: { getItem() { return null; }, setItem() {} } },
    WebSocket: FakeWebSocket,
    fetch: (url, options) => {
      requests.push({ url, ...options });
      return fetchImpl(url, options, requests.length);
    },
    URL: class extends URL {
      static createObjectURL(blob) { downloads.push(blob); return "blob:download"; }
      static revokeObjectURL() {}
    },
  };
  const originals = Object.keys(globals).map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]);
  Object.assign(globalThis, globals);
  t.after(async () => {
    for (const socket of sockets) socket.emit("error");
    await tick();
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  });
  await import(`./app.js?test=${++moduleId}`);
  return {
    elements, requests, downloads, document,
    upload(file = makeFile()) {
      elements.uploadCBOM.files = file ? [file] : [];
      elements.uploadCBOM.value = file ? file.name : "";
      return elements.uploadCBOM.listeners.change();
    },
    scan() {
      elements.repoUrl.value = "https://github.com/example/project";
      return elements.complianceForm.listeners.submit({ preventDefault() {} });
    },
    finishScan() {
      const socket = sockets.at(-1);
      socket.emit("open");
      socket.emit("message", { data: JSON.stringify({ type: "CBOM", message: cbom }) });
      socket.emit("message", { data: JSON.stringify({ type: "LABEL", message: "Finished" }) });
    },
  };
}

test("upload evaluates policies without a repository and preserves the download", async t => {
  const pending = deferred();
  const app = await loadApp(t, () => pending.promise);
  const finished = app.upload();
  assert.equal(app.elements.checkButton.disabled, true);
  assert.equal(app.elements.uploadCbomButton.disabled, true);
  assert.equal(app.elements.uploadCBOM.disabled, true);
  assert.equal(app.elements.uploadCBOM.value, "");
  await tick();
  assert.equal(app.requests.length, 1);
  assert.match(app.requests[0].url, /\/v1\/data\/cbom\/eccg$/);
  assert.deepEqual(JSON.parse(app.requests[0].body), { input: cbom });
  pending.resolve(policyResponse());
  await finished;
  assert.equal(app.elements.results.hidden, false);
  assert.equal(app.elements.resultsTitle.textContent, "CBOM policy result");
  assert.match(app.elements.complianceBanner.innerHTML, /CBOM policy check passed/);
  assert.match(app.elements.summary.innerHTML, /Not run/);
  assert.match(app.elements.semgrepResults.innerHTML, /Not run/);
  assert.match(app.elements.status.textContent, /Semgrep not run/);
  assert.equal(app.elements.errorBox.hidden, true);
  assert.equal(app.elements.checkButton.disabled, false);
  assert.equal(app.elements.uploadCbomButton.disabled, false);
  assert.equal(app.elements.uploadCBOM.disabled, false);
  assert.equal(app.elements.downloadCbomButton.hidden, false);
  assert.equal(app.elements.downloadCbomButton.disabled, false);
  app.elements.downloadCbomButton.click();
  assert.deepEqual(JSON.parse(await app.downloads[0].text()), cbom);
  assert.equal(app.document.body.children.at(-1).download, "uploaded.json");
});

test("blocking upload findings fail the CBOM policy check", async t => {
  const app = await loadApp(t, async () => policyResponse([
    { severity: "high", ruleId: "TEST", component: "AES", message: "Blocked algorithm" },
  ]));
  await app.upload();
  assert.match(app.elements.complianceBanner.innerHTML, /CBOM policy check failed/);
  assert.match(app.elements.status.textContent, /finished: failed/);
});

test("invalid files show errors without a policy request or stale passing result", async t => {
  const app = await loadApp(t);
  await app.upload();
  for (const [file, expected] of [
    [makeFile("{ broken"), /not valid JSON/],
    [makeFile('{"hello":"world"}'), /CycloneDX CBOM/],
    [makeFile("{}", "wrong.txt"), /\.json extension/],
    [{ name: "unreadable.json", text: async () => { throw new Error("unreadable"); } }, /Could not read/],
  ]) {
    await app.upload(file);
    assert.equal(app.requests.length, 1);
    assert.equal(app.elements.results.hidden, true);
    assert.equal(app.elements.downloadCbomButton.hidden, true);
    assert.equal(app.elements.errorBox.hidden, false);
    assert.match(app.elements.errorBox.textContent, expected);
    assert.equal(app.elements.uploadCbomButton.disabled, false);
    assert.equal(app.elements.uploadCBOM.value, "");
  }
});

test("empty file selection preserves the last result and the same file can be retried", async t => {
  const app = await loadApp(t);
  await app.upload(null);
  assert.equal(app.requests.length, 0);
  const file = makeFile();
  await app.upload(file);
  await app.upload(null);
  assert.equal(app.elements.results.hidden, false);
  assert.equal(app.elements.errorBox.hidden, true);
  await app.upload(file);
  assert.equal(app.requests.length, 2);
});

test("policy errors and missing decisions cannot appear as passing uploads", async t => {
  const replies = [
    response({ message: "Policy unavailable" }, false),
    response({}),
    response({ result: {} }),
    { ok: true, text: async () => "not JSON" },
  ];
  const app = await loadApp(t, async () => replies.shift());
  for (let i = 0; i < 4; i++) {
    await app.upload();
    assert.equal(app.elements.results.hidden, true);
    assert.equal(app.elements.errorBox.hidden, false);
    assert.match(app.elements.errorBox.textContent, /Policy unavailable|valid findings result/);
    assert.equal(app.elements.checkButton.disabled, false);
  }
});

test("cancelled upload cannot clear a newer repository scan's controller", async t => {
  const app = await loadApp(t, (url, { signal }, count) => {
    if (count === 1) {
      return new Promise((resolve, reject) => signal.addEventListener("abort", () => {
        reject(new DOMException("Aborted", "AbortError"));
      }));
    }
    return Promise.resolve(url.endsWith("/scan")
      ? response({ ok: true, result: { findings: [] } })
      : policyResponse());
  });
  const upload = app.upload();
  await tick();
  // Force overlapping events to verify cancellation even though controls are disabled.
  const scan = app.scan();
  await upload;
  assert.equal(app.requests[0].signal.aborted, true);
  assert.equal(app.elements.errorBox.hidden, true);
  assert.equal(app.elements.checkButton.disabled, true);
  app.finishScan();
  await scan;
  assert.equal(app.requests.length, 3);
  assert.equal(app.requests[1].signal, app.requests[2].signal);
  assert.equal(app.requests[2].signal.aborted, false);
  assert.equal(app.elements.errorBox.hidden, true);
  assert.equal(app.elements.resultsTitle.textContent, "Compliance result");
  assert.match(app.elements.status.textContent, /finished: compliant$/);
  assert.doesNotMatch(app.elements.summary.innerHTML, /Not run/);
});

test("late policy responses cannot overwrite a newer upload", async t => {
  const stale = deferred();
  const current = deferred();
  const app = await loadApp(t, (url, options, count) => count === 1 ? stale.promise : current.promise);
  const first = app.upload();
  await tick();
  const second = app.upload(makeFile(JSON.stringify(cbom), "new.json"));
  await tick();
  stale.resolve(policyResponse([{ severity: "high", message: "Stale finding" }]));
  await first;
  assert.equal(app.elements.results.hidden, true);
  assert.equal(app.elements.checkButton.disabled, true);
  current.resolve(policyResponse());
  await second;
  assert.match(app.elements.status.textContent, /finished: passed/);
  app.elements.downloadCbomButton.click();
  assert.equal(app.document.body.children.at(-1).download, "new.json");
});

test("a missing Semgrep result fails a repository check instead of appearing skipped", async t => {
  const app = await loadApp(t, async url => url.endsWith("/scan")
    ? response(null)
    : policyResponse());
  const scan = app.scan();
  app.finishScan();
  await scan;
  assert.equal(app.elements.results.hidden, true);
  assert.equal(app.elements.errorBox.hidden, false);
  assert.match(app.elements.errorBox.textContent, /Semgrep did not return a valid findings result/);
  assert.equal(app.elements.checkButton.disabled, false);
});

test("a superseded file read cannot send a request or change the active result", async t => {
  const reading = deferred();
  const app = await loadApp(t);
  const first = app.upload({ name: "slow.json", text: () => reading.promise });
  const second = app.upload(makeFile(JSON.stringify(cbom), "new.json"));
  await second;
  reading.resolve(JSON.stringify(cbom));
  await first;
  assert.equal(app.requests.length, 1);
  assert.equal(app.elements.errorBox.hidden, true);
  app.elements.downloadCbomButton.click();
  assert.equal(app.document.body.children.at(-1).download, "new.json");
});
