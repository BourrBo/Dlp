/**
 * Background service worker. Authentication and backend requests stay out of
 * content scripts; refresh tokens are kept in extension-local storage.
 */

const DEFAULT_CONFIG = {
  backendUrl: "http://localhost:8000",
  supabaseUrl: "",
  supabasePublishableKey: "",
  orgId: "",
  enabled: true,
};

const VALID_DECISIONS = new Set(["allow", "warn", "block", "log"]);
const VALID_DATA_TYPES = new Set([
  "credit_card",
  "api_key",
  "email_pii",
  "national_id",
  "person_name",
  "address",
  "phone_number",
  "document_match",
  "custom",
]);
const authStorageReady = chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
let refreshInProgress;

async function getConfig() {
  const stored = await chrome.storage.sync.get(DEFAULT_CONFIG);
  return { ...DEFAULT_CONFIG, ...stored };
}

function isValidScanResult(result) {
  return (
    result !== null &&
    typeof result === "object" &&
    Array.isArray(result.findings) &&
    result.findings.every((finding) =>
      finding !== null &&
      typeof finding === "object" &&
      typeof finding.id === "string" &&
      VALID_DATA_TYPES.has(finding.data_type) &&
      Number.isFinite(finding.confidence) &&
      finding.confidence >= 0 &&
      finding.confidence <= 1 &&
      typeof finding.matched_snippet === "string" &&
      typeof finding.sensitivity_level === "string" &&
      (finding.matched_rule_id === null || typeof finding.matched_rule_id === "string") &&
      (finding.label === null || typeof finding.label === "string")
    ) &&
    VALID_DECISIONS.has(result.decision) &&
    typeof result.reason === "string" &&
    Object.hasOwn(result, "matched_policy_id") &&
    (result.matched_policy_id === null || typeof result.matched_policy_id === "string")
  );
}

function isValidSession(response) {
  return (
    response !== null &&
    typeof response === "object" &&
    typeof response.access_token === "string" &&
    response.access_token.length > 0 &&
    typeof response.refresh_token === "string" &&
    response.refresh_token.length > 0 &&
    Number.isFinite(response.expires_in) &&
    response.expires_in > 0
  );
}

function isPublicSupabaseKey(key) {
  if (key.startsWith("sb_publishable_")) return true;
  try {
    const payload = JSON.parse(atob(key.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return payload.role === "anon";
  } catch {
    return false;
  }
}

function secureBaseUrl(value, service) {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
    throw new Error(`${service} URL must use HTTPS.`);
  }
  if (url.username || url.password) {
    throw new Error(`${service} URL must not contain credentials.`);
  }
  return url.href.replace(/\/+$/, "");
}

async function requestAuthToken(config, body) {
  const baseUrl = secureBaseUrl(config.supabaseUrl, "Supabase");
  if (!isPublicSupabaseKey(config.supabasePublishableKey)) {
    throw new Error("Configure a Supabase publishable key or legacy anon key.");
  }

  const response = await fetch(`${baseUrl}/auth/v1/token?grant_type=${body.grant_type}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: config.supabasePublishableKey,
    },
    body: JSON.stringify(body.payload),
  });
  if (!response.ok) {
    throw new Error(response.status === 400 || response.status === 401
      ? "Supabase sign-in failed. Check your credentials."
      : `Supabase authentication returned ${response.status}.`);
  }

  const result = await response.json();
  if (!isValidSession(result)) {
    throw new Error("Supabase returned an invalid authentication session.");
  }
  return {
    access_token: result.access_token,
    refresh_token: result.refresh_token,
    expires_at: Date.now() + result.expires_in * 1000,
    email: typeof result.user?.email === "string" ? result.user.email : "",
  };
}

async function signIn(email, password) {
  if (typeof email !== "string" || !email.trim() || typeof password !== "string" || !password) {
    throw new Error("Enter your Supabase account email and password.");
  }
  const config = await getConfig();
  const session = await requestAuthToken(config, {
    grant_type: "password",
    payload: { email: email.trim(), password },
  });
  await authStorageReady;
  await chrome.storage.local.set({ authSession: session });
  return { authenticated: true, email: session.email };
}

async function signOut() {
  await authStorageReady;
  await chrome.storage.local.remove("authSession");
  return { authenticated: false, email: "" };
}

async function refreshSession(session, config) {
  const refreshed = await requestAuthToken(config, {
    grant_type: "refresh_token",
    payload: { refresh_token: session.refresh_token },
  });
  await chrome.storage.local.set({ authSession: refreshed });
  return refreshed;
}

async function getAccessToken() {
  await authStorageReady;
  const [{ authSession }, config] = await Promise.all([
    chrome.storage.local.get("authSession"),
    getConfig(),
  ]);
  if (!authSession?.access_token || !authSession?.refresh_token) {
    throw new Error("Sign in to Supabase in the extension settings before scanning.");
  }
  if (authSession.expires_at > Date.now() + 30_000) {
    return authSession.access_token;
  }

  if (!refreshInProgress) {
    refreshInProgress = refreshSession(authSession, config).finally(() => {
      refreshInProgress = undefined;
    });
  }
  try {
    return (await refreshInProgress).access_token;
  } catch (error) {
    await signOut();
    throw error;
  }
}

async function saveConfig(config) {
  const previous = await getConfig();
  if (
    config.supabaseUrl !== previous.supabaseUrl ||
    config.supabasePublishableKey !== previous.supabasePublishableKey
  ) {
    await signOut();
  }
  const values = {
    backendUrl: config.backendUrl.trim(),
    supabaseUrl: config.supabaseUrl.trim(),
    supabasePublishableKey: config.supabasePublishableKey.trim(),
    orgId: config.orgId.trim(),
  };
  await chrome.storage.sync.set(values);
  await chrome.storage.sync.remove("userId");
  return { saved: true };
}

async function getAuthState() {
  const { authSession } = await chrome.storage.local.get("authSession");
  return {
    authenticated: Boolean(authSession?.refresh_token),
    email: authSession?.email ?? "",
  };
}

async function scan({ content, channel, destination, filename }) {
  const config = await getConfig();

  if (!config.enabled) {
    return { decision: "allow", findings: [], reason: "Protection disabled" };
  }
  if (!config.orgId) {
    return { decision: "block", findings: [], reason: "Configure an organization in extension settings." };
  }

  try {
    const accessToken = await getAccessToken();
    const backendUrl = secureBaseUrl(config.backendUrl, "Backend");
    const res = await fetch(`${backendUrl}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        org_id: config.orgId,
        channel,
        destination,
        content,
        filename: filename ?? null,
      }),
    });
    if (!res.ok) {
      throw new Error(`Backend returned ${res.status}`);
    }
    const result = await res.json();
    if (!isValidScanResult(result)) {
      throw new Error("Backend returned an invalid scan result");
    }
    return result;
  } catch (error) {
    return { decision: "block", findings: [], reason: `Scan failed: ${error.message}` };
  }
}

async function logLocalEvent(entry) {
  const { recentEvents = [] } = await chrome.storage.local.get("recentEvents");
  const updated = [{ ...entry, at: Date.now() }, ...recentEvents].slice(0, 25);
  await chrome.storage.local.set({ recentEvents: updated });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "DLP_SIGN_IN") {
    signIn(message.email, message.password)
      .then(sendResponse)
      .catch((error) => sendResponse({ authenticated: false, error: error.message }));
    return true;
  }
  if (message.type === "DLP_SIGN_OUT") {
    signOut().then(sendResponse).catch((error) => sendResponse({ error: error.message }));
    return true;
  }
  if (message.type === "DLP_AUTH_STATE") {
    getAuthState().then(sendResponse).catch((error) => sendResponse({ error: error.message }));
    return true;
  }
  if (message.type === "DLP_SAVE_CONFIG") {
    saveConfig(message.config)
      .then(sendResponse)
      .catch((error) => sendResponse({ error: error.message }));
    return true;
  }
  if (message.type !== "DLP_SCAN") return false;

  scan(message.payload)
    .then(async (result) => {
      await logLocalEvent({
        decision: result.decision,
        reason: result.reason,
        destination: message.payload.destination,
        channel: message.payload.channel,
      });
      sendResponse(result);
    })
    .catch((error) => sendResponse({ decision: "block", findings: [], reason: `Extension error: ${error.message}` }));

  return true;
});
