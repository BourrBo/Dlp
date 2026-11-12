/**
 * MV3 worker owns all API-key use. The key never crosses into page context.
 * chrome.storage.managed wins over local unpacked-development settings.
 */
if (!globalThis.DlpExtension && typeof importScripts === "function") {
  importScripts("extension-core.js", "personal-auth.js");
}

// Keep managed secrets out of the content-script execution context. Page
// scripts are isolated already; this also narrows storage access to trusted
// extension pages and the service worker.
function restrictStorage(area) {
  try {
    return Promise.resolve(area.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" })).catch(() => undefined);
  } catch {
    return Promise.resolve();
  }
}

void Promise.all([restrictStorage(chrome.storage.local), restrictStorage(chrome.storage.managed)]);

const DEFAULT_CONFIG = {
  backendUrl: "http://localhost:8000",
  apiKey: "",
  supabaseUrl: "",
  supabasePublishableKey: "",
  aiSites: DlpExtension.DEFAULT_AI_SITES,
  enabled: true,
  failClosed: false,
};

async function readConfig() {
  let managed = {};
  try {
    managed = await chrome.storage.managed.get(null);
  } catch {
    // Managed storage is unavailable for unpacked developer installs.
  }
  const managedKeys = Object.keys(managed);
  const local = await chrome.storage.local.get(DEFAULT_CONFIG);
  const config = { ...DEFAULT_CONFIG, ...local, ...managed };
  config.aiSites = DlpExtension.normalizeSites(config.aiSites);
  try {
    const url = new URL(config.backendUrl);
    if (!new Set(["http:", "https:"]).has(url.protocol) || url.username || url.password) {
      throw new Error("Backend URL must be an HTTP(S) origin without credentials.");
    }
    config.backendUrl = url.origin;
    config.configError = "";
  } catch (err) {
    config.configError = err.message || "Invalid backend URL.";
  }
  config.managedKeys = managedKeys;
  return config;
}

function hasCredentials(config) {
  return Boolean(config.apiKey) || DlpPersonalAuth.isConfigured(config);
}

// A scoped API key wins; otherwise the signed-in user's session token is used.
// Either way the credential stays inside this worker.
async function authHeader(config) {
  if (config.apiKey) return { Authorization: `Bearer ${config.apiKey}` };
  return { Authorization: `Bearer ${await DlpPersonalAuth.getAccessToken(config)}` };
}

function unavailable(config, reason) {
  return {
    decision: config.failClosed ? "block" : "allow",
    findings: [],
    reason,
    unavailable: true,
  };
}

async function scan({ content, channel, destination, filename }) {
  let config;
  try {
    config = await readConfig();
  } catch {
    return { decision: "block", findings: [], reason: "DLP configuration could not be read; submission blocked for safety.", unavailable: true };
  }
  const host = DlpExtension.normalizeHost(destination);
  if (!config.enabled) return { decision: "allow", findings: [], reason: "Protection disabled" };
  if (!DlpExtension.isProtectedDestination(host, config.aiSites)) {
    return { decision: "allow", findings: [], reason: "Destination is not monitored" };
  }
  if (config.configError) return unavailable(config, config.configError);
  if (!hasCredentials(config)) return unavailable(config, "No DLP credentials are configured. Ask your administrator for an API key or sign in from settings.");

  try {
    const response = await fetch(`${config.backendUrl}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(await authHeader(config)),
      },
      body: JSON.stringify({
        channel,
        destination: host,
        content,
        filename: filename ?? null,
      }),
    });
    if (response.status === 401 || response.status === 403) {
      return unavailable(config, "DLP credentials were rejected or revoked. Contact your administrator.");
    }
    if (!response.ok) throw new Error(`DLP API returned HTTP ${response.status}.`);
    return await response.json();
  } catch (err) {
    return unavailable(config, `DLP service unavailable: ${err.message || "request failed"}`);
  }
}

async function testConnection() {
  const config = await readConfig();
  if (config.configError) throw new Error(config.configError);
  const response = await fetch(`${config.backendUrl}/health`);
  if (!response.ok) throw new Error(`DLP backend returned HTTP ${response.status}.`);
  return response.json();
}

function timedFetch(url, options, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

function uploadUnavailable(config, reason) {
  return { decision: config.failClosed ? "block" : "allow", findings: [], reason, unavailable: true };
}

function summarizeJob(job, config) {
  const files = job.result?.files ?? [];
  const skipped = files.find((file) => file.skipped_reason);
  if (skipped) return uploadUnavailable(config, `File was not scanned: ${skipped.skipped_reason}`);
  const chunks = files.flatMap((file) => file.chunks ?? []);
  if (!chunks.length) return uploadUnavailable(config, "The scan job completed without a file-scan result.");

  const ranks = { block: 4, warn: 3, log: 2, allow: 1 };
  const strictest = chunks.reduce((current, chunk) =>
    !current || (ranks[chunk.decision] ?? 0) > (ranks[current.decision] ?? 0) ? chunk : current, null);
  return {
    decision: strictest.decision,
    findings: chunks.flatMap((chunk) => chunk.findings ?? []),
    reason: strictest.reason,
    jobId: job.id,
  };
}

async function submitAndPollFile(config, host, state, port) {
  const blob = new Blob(state.chunks, { type: state.contentType || "application/octet-stream" });
  const body = new FormData();
  body.append("file", blob, state.filename);
  body.append("destination", host);
  let response = await timedFetch(`${config.backendUrl}/scan-jobs`, {
    method: "POST",
    headers: await authHeader(config),
    body,
  });
  if (response.status === 401 || response.status === 403) {
    throw new Error("DLP credentials were rejected or revoked. Contact your administrator.");
  }
  if (response.status === 404 || response.status === 422) {
    throw new Error("The backend rejected the file-scan request. Check the backend version and your API key scope.");
  }
  if (!response.ok) throw new Error(`DLP file-scan API returned HTTP ${response.status}.`);
  let job = await response.json();
  state.jobId = job.id;
  state.chunks = [];
  state.receivedBytes = 0;
  port.postMessage({ type: "JOB", jobId: job.id, status: job.status, progress: job.progress });

  let waitMs = 500;
  const deadline = Date.now() + 180000;
  while (Date.now() < deadline) {
    if (job.status === "completed") return summarizeJob(job, config);
    if (job.status === "failed" || job.status === "cancelled") {
      throw new Error(job.error_message || `File scan ${job.status}.`);
    }
    await new Promise((resolve) => setTimeout(resolve, waitMs));
    response = await timedFetch(`${config.backendUrl}/scan-jobs/${encodeURIComponent(job.id)}`, {
      headers: await authHeader(config),
    });
    if (response.status === 401 || response.status === 403) {
      throw new Error("DLP credentials were rejected or revoked. Contact your administrator.");
    }
    if (response.status === 404 || response.status === 422) {
      throw new Error("The backend rejected the scan-job status request. Check the backend version and your API key scope.");
    }
    if (!response.ok) throw new Error(`DLP scan-job status returned HTTP ${response.status}.`);
    job = await response.json();
    port.postMessage({ type: "PROGRESS", status: job.status, phase: job.phase, progress: job.progress });
    waitMs = Math.min(waitMs + 500, 3000);
  }
  throw new Error("File scan exceeded the 3 minute browser wait limit.");
}

async function startFileScan(port, message, state) {
  const config = await readConfig();
  state.config = config;
  const host = DlpExtension.normalizeHost(message.destination);
  if (!config.enabled || !DlpExtension.isProtectedDestination(host, config.aiSites)) {
    port.postMessage({ type: "DONE", result: { decision: "allow", findings: [], reason: "Protection disabled or destination not monitored" } });
    return;
  }
  if (config.configError) throw new Error(config.configError);
  if (!hasCredentials(config)) throw new Error("No DLP credentials are configured. Ask your administrator for an API key or sign in from settings.");
  if (!Number.isSafeInteger(message.size) || message.size < 1 || message.size > 25 * 1024 * 1024) {
    throw new Error("File must be between 1 byte and 25 MiB.");
  }

  const senderHost = DlpExtension.normalizeHost(port.sender?.tab?.url ?? port.sender?.url ?? "");
  if (!DlpExtension.isProtectedDestination(senderHost, config.aiSites) || senderHost !== host) {
    throw new Error("The scan destination did not match the protected browser tab.");
  }
  state.filename = String(message.filename || "uploaded-file").slice(0, 200);
  state.size = message.size;
  state.contentType = String(message.contentType || "application/octet-stream").slice(0, 120);
  state.receivedBytes = 0;
  state.nextSequence = 0;
  state.chunks = [];
  port.postMessage({ type: "READY", chunkBytes: 32768 });
}

chrome.runtime.onConnect?.addListener((port) => {
  if (port.name !== "DLP_FILE_SCAN") return;
  const state = { chunks: [], receivedBytes: 0, jobId: "", finished: false, config: { failClosed: true } };

  port.onMessage.addListener((message) => {
    void (async () => {
      if (message.type === "START") {
        await startFileScan(port, message, state);
        return;
      }
      if (message.type === "CHUNK") {
        if (!state.config || state.finished || message.sequence !== state.nextSequence || typeof message.data !== "string") {
          throw new Error("File transfer sequence is invalid.");
        }
        const binary = atob(message.data);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
        state.receivedBytes += bytes.length;
        if (state.receivedBytes > state.size) throw new Error("File transfer exceeded the declared size.");
        state.chunks.push(bytes);
        port.postMessage({ type: "ACK", sequence: state.nextSequence });
        state.nextSequence += 1;
        return;
      }
      if (message.type === "FINISH") {
        if (!state.config || state.finished || state.receivedBytes !== state.size) {
          throw new Error("File transfer was incomplete.");
        }
        state.finished = true;
        const result = await submitAndPollFile(state.config, DlpExtension.normalizeHost(port.sender?.tab?.url ?? ""), state, port);
        state.terminal = true;
        port.postMessage({ type: "DONE", result });
        await logLocalEvent({ decision: result.decision, reason: result.reason, destination: DlpExtension.normalizeHost(port.sender?.tab?.url ?? ""), channel: "browser" });
        return;
      }
      throw new Error("Unknown file-transfer message.");
    })().catch((err) => {
      const result = state.config
        ? uploadUnavailable(state.config, err.message || "File scan failed.")
        : { decision: "allow", findings: [], reason: err.message || "File scan failed.", unavailable: true };
      try { port.postMessage({ type: "DONE", result }); } catch { /* sender disconnected */ }
    });
  });

  port.onDisconnect.addListener(() => {
    state.chunks = [];
    if (state.jobId && !state.terminal && hasCredentials(state.config ?? {})) {
      void authHeader(state.config).then((headers) => timedFetch(`${state.config.backendUrl}/scan-jobs/${encodeURIComponent(state.jobId)}`, {
        method: "DELETE",
        headers,
      })).catch(() => undefined);
    }
  });
});

async function logLocalEvent(entry) {
  const { recentEvents = [] } = await chrome.storage.local.get("recentEvents");
  const updated = [{ ...entry, at: Date.now() }, ...recentEvents].slice(0, 25);
  await chrome.storage.local.set({ recentEvents: updated });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "DLP_TEST_CONNECTION") {
    testConnection().then(sendResponse).catch((err) => sendResponse({ error: err.message }));
    return true;
  }
  if (message.type === "DLP_GET_CONFIG") {
    readConfig().then((config) => {
      const { backendUrl, aiSites, enabled, failClosed, apiKey, configError, managedKeys, supabaseUrl } = config;
      return DlpPersonalAuth.getAuthState().then((auth) =>
        sendResponse({ backendUrl, aiSites, enabled, failClosed, configured: Boolean(apiKey) || auth.authenticated, usingApiKey: Boolean(apiKey), signedInAs: auth.authenticated ? auth.email : "", supabaseUrl, configError, managedKeys })
      );
    }
    ).catch(() => sendResponse({ backendUrl: "", aiSites: [], enabled: true, failClosed: true, configured: false, configError: "DLP configuration could not be read." }));
    return true;
  }
  if (message.type === "DLP_SIGN_IN") {
    readConfig()
      .then((config) => DlpPersonalAuth.signIn(config, message.email, message.password))
      .then(sendResponse)
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }
  if (message.type === "DLP_SIGN_OUT") {
    DlpPersonalAuth.signOut().then(sendResponse).catch((err) => sendResponse({ error: err.message }));
    return true;
  }
  if (message.type !== "DLP_SCAN") return false;

  scan(message.payload)
    .then((result) => {
      void logLocalEvent({
        decision: result.decision,
        reason: result.reason,
        destination: DlpExtension.normalizeHost(message.payload.destination),
        channel: message.payload.channel,
      }).catch(() => undefined);
      sendResponse(result);
    })
    .catch((err) => sendResponse({ decision: "block", findings: [], reason: `DLP scan failed; submission blocked for safety: ${err.message}`, unavailable: true }));

  return true;
});
