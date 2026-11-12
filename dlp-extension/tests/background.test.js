const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadWorker({ managed = {}, local = {}, fetchImpl, failLocalRead = false }) {
  const listeners = [];
  const connectionListeners = [];
  const state = { local: { ...local }, managed: { ...managed } };
  const area = (name) => ({
    get: async (keys) => {
      if (name === "local" && failLocalRead) throw new Error("Storage read failed");
      const values = state[name];
      if (keys === null || keys === undefined) return { ...values };
      if (Array.isArray(keys)) return Object.fromEntries(keys.filter((key) => key in values).map((key) => [key, values[key]]));
      if (typeof keys === "string") return keys in values ? { [keys]: values[keys] } : {};
      return { ...keys, ...values };
    },
    set: async (values) => Object.assign(state[name], values),
    remove: async (key) => delete state[name][key],
    setAccessLevel: async () => undefined,
  });
  const context = vm.createContext({
    URL,
    Set,
    Promise,
    Date,
    fetch: fetchImpl,
    AbortController,
    Blob,
    FormData,
    atob,
    btoa,
    setTimeout,
    clearTimeout,
    chrome: {
      storage: { local: area("local"), managed: area("managed") },
      runtime: {
        onMessage: { addListener: (fn) => listeners.push(fn) },
        onConnect: { addListener: (fn) => connectionListeners.push(fn) },
      },
    },
    importScripts: (...files) => {
      for (const file of files) vm.runInContext(fs.readFileSync(path.join(__dirname, "..", file), "utf8"), context);
    },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8"), context);
  return {
    state,
    send: (message) => new Promise((resolve) => listeners[0](message, {}, resolve)),
    connect: (port) => connectionListeners.forEach((listener) => listener(port)),
  };
}

test("managed settings take precedence and the worker sends a key without caller-selected tenant IDs", async () => {
  let request;
  const worker = loadWorker({
    local: { backendUrl: "https://wrong.example", apiKey: "local-key", aiSites: ["chatgpt.com"] },
    managed: { backendUrl: "https://dlp.example", apiKey: "managed-key", aiSites: ["claude.ai"], enabled: true, failClosed: true },
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { status: 200, ok: true, json: async () => ({ decision: "allow", findings: [], reason: "clear" }) };
    },
  });
  const result = await worker.send({
    type: "DLP_SCAN",
    payload: { content: "synthetic sample", channel: "browser", destination: "www.claude.ai/path" },
  });
  assert.equal(result.decision, "allow");
  assert.equal(request.url, "https://dlp.example/api/scan");
  assert.equal(request.options.headers.Authorization, "Bearer managed-key");
  const body = JSON.parse(request.options.body);
  assert.equal(body.destination, "claude.ai");
  assert.equal("org_id" in body, false);
  assert.equal("user_id" in body, false);
  assert.equal(worker.state.local.apiKey, "local-key");
});

test("reports revoked keys clearly and follows fail-closed policy", async () => {
  const worker = loadWorker({
    managed: { apiKey: "revoked", aiSites: ["chatgpt.com"], failClosed: true },
    fetchImpl: async () => ({ status: 401, ok: false }),
  });
  const result = await worker.send({ type: "DLP_SCAN", payload: { content: "sample text", channel: "browser", destination: "chatgpt.com" } });
  assert.equal(result.decision, "block");
  assert.match(result.reason, /rejected or revoked/i);
});

test("streams an uploaded file to the authenticated durable job API without tenant IDs", async () => {
  let uploadRequest;
  const worker = loadWorker({
    managed: { backendUrl: "https://dlp.example", apiKey: "managed-key", aiSites: ["chatgpt.com"], enabled: true, failClosed: true },
    fetchImpl: async (url, options) => {
      uploadRequest = { url, options };
      return {
        status: 202,
        ok: true,
        json: async () => ({
          id: "job-123",
          status: "completed",
          progress: 100,
          result: { files: [{ chunks: [{ decision: "allow", reason: "No sensitive data", findings: [] }] }] },
        }),
      };
    },
  });
  const messages = [];
  const messageListeners = [];
  const disconnectListeners = [];
  const port = {
    name: "DLP_FILE_SCAN",
    sender: { tab: { url: "https://chatgpt.com/" } },
    onMessage: { addListener: (fn) => messageListeners.push(fn) },
    onDisconnect: { addListener: (fn) => disconnectListeners.push(fn) },
    postMessage: (message) => messages.push(message),
    disconnect: () => disconnectListeners.forEach((fn) => fn()),
  };
  worker.connect(port);
  const send = (message) => messageListeners.forEach((listener) => listener(message));
  const waitFor = async (type) => {
    for (let i = 0; i < 100; i += 1) {
      const found = messages.find((message) => message.type === type);
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    throw new Error(`Timed out waiting for ${type}`);
  };

  send({ type: "START", filename: "invoice.pdf", size: 4, contentType: "application/pdf", destination: "chatgpt.com" });
  await waitFor("READY");
  send({ type: "CHUNK", sequence: 0, data: Buffer.from("PDF!").toString("base64") });
  await waitFor("ACK");
  send({ type: "FINISH" });
  const done = await waitFor("DONE");

  assert.equal(done.result.decision, "allow");
  assert.equal(done.result.jobId, "job-123");
  assert.equal(uploadRequest.url, "https://dlp.example/scan-jobs");
  assert.equal(uploadRequest.options.headers.Authorization, "Bearer managed-key");
  assert.deepEqual([...uploadRequest.options.body.keys()].sort(), ["destination", "file"]);
  const uploadedFile = uploadRequest.options.body.get("file");
  assert.equal(Buffer.from(await uploadedFile.arrayBuffer()).toString(), "PDF!");
  assert.equal(uploadRequest.options.body.get("destination"), "chatgpt.com");
});

test("missing managed key on file scan follows fail-closed setting", async () => {
  const worker = loadWorker({
    managed: { backendUrl: "https://dlp.example", aiSites: ["chatgpt.com"], failClosed: true },
    fetchImpl: async () => { throw new Error("A request should not be sent without a key."); },
  });
  const messages = [];
  const messageListeners = [];
  const port = {
    name: "DLP_FILE_SCAN",
    sender: { tab: { url: "https://chatgpt.com/" } },
    onMessage: { addListener: (fn) => messageListeners.push(fn) },
    onDisconnect: { addListener: () => undefined },
    postMessage: (message) => messages.push(message),
    disconnect: () => undefined,
  };
  worker.connect(port);
  messageListeners[0]({ type: "START", filename: "secret.pdf", size: 100, destination: "chatgpt.com" });
  for (let i = 0; i < 100 && !messages.some((message) => message.type === "DONE"); i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const done = messages.find((message) => message.type === "DONE");
  assert.ok(done);
  assert.equal(done.result.decision, "block");
  assert.match(done.result.reason, /no dlp credentials are configured/i);
});

test("unreadable extension configuration blocks both text and file scans", async () => {
  const worker = loadWorker({
    fetchImpl: async () => { throw new Error("A request should not be sent when configuration cannot load."); },
    failLocalRead: true,
  });
  const textResult = await worker.send({
    type: "DLP_SCAN",
    payload: { content: "synthetic card value", channel: "browser", destination: "chatgpt.com" },
  });
  assert.equal(textResult.decision, "block");
  assert.match(textResult.reason, /configuration could not be read/i);

  const messages = [];
  const messageListeners = [];
  const port = {
    name: "DLP_FILE_SCAN",
    sender: { tab: { url: "https://chatgpt.com/" } },
    onMessage: { addListener: (fn) => messageListeners.push(fn) },
    onDisconnect: { addListener: () => undefined },
    postMessage: (message) => messages.push(message),
    disconnect: () => undefined,
  };
  worker.connect(port);
  messageListeners[0]({ type: "START", filename: "scan.pdf", size: 100, destination: "chatgpt.com" });
  for (let i = 0; i < 100 && !messages.some((message) => message.type === "DONE"); i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  assert.equal(messages.find((message) => message.type === "DONE")?.result.decision, "block");
});

test("personal sign-in session is used when no API key is configured", async () => {
  const calls = [];
  const worker = loadWorker({
    local: {
      backendUrl: "http://localhost:8000",
      supabaseUrl: "https://abc.supabase.co",
      supabasePublishableKey: "sb_publishable_test",
      authSession: { access_token: "user-jwt", refresh_token: "r", expires_at: Date.now() + 3600000, email: "a@b.com" },
    },
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return { ok: true, status: 200, json: async () => ({ decision: "allow", findings: [], reason: "ok" }) };
    },
  });
  const result = await worker.send({ type: "DLP_SCAN", payload: { content: "hi", channel: "browser", destination: "chatgpt.com" } });
  assert.equal(result.decision, "allow");
  assert.equal(calls[0].init.headers.Authorization, "Bearer user-jwt");
  assert.equal(JSON.parse(calls[0].init.body).org_id, undefined);
});
