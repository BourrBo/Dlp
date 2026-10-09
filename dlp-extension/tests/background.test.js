const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8");

function createExtension({
  authStatus = 200,
  scanStatus = 200,
  scanResult = null,
  backendUrl = "https://backend.example",
  supabasePublishableKey = "sb_publishable_public",
} = {}) {
  let listener;
  const calls = [];
  const syncValues = {
    backendUrl,
    supabaseUrl: "https://project.supabase.co",
    supabasePublishableKey,
    orgId: "org-to-check",
    enabled: true,
  };
  const localValues = {};

  const context = {
    URL,
    Date,
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (url.includes("/auth/v1/token?grant_type=password")) {
        return {
          ok: authStatus === 200,
          status: authStatus,
          json: async () => ({
            access_token: "short-lived-access-token",
            refresh_token: "refresh-token",
            expires_in: 3600,
            user: { email: "member@example.com", id: "must-not-be-used" },
          }),
        };
      }
      if (url.includes("/auth/v1/token?grant_type=refresh_token")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            access_token: "refreshed-access-token",
            refresh_token: "rotated-refresh-token",
            expires_in: 3600,
          }),
        };
      }
      return {
        ok: scanStatus === 200,
        status: scanStatus,
        json: async () => scanResult ?? ({
          findings: [],
          decision: "allow",
          matched_policy_id: null,
          reason: "No policy matched",
        }),
      };
    },
    chrome: {
      storage: {
        sync: {
          get: async (defaults) => ({ ...defaults, ...syncValues }),
          set: async (values) => Object.assign(syncValues, values),
          remove: async (key) => { delete syncValues[key]; },
        },
        local: {
          setAccessLevel: async () => {},
          get: async (key) => ({ [key]: localValues[key] }),
          set: async (values) => Object.assign(localValues, values),
          remove: async (key) => { delete localValues[key]; },
        },
      },
      runtime: { onMessage: { addListener: (fn) => { listener = fn; } } },
    },
  };
  vm.runInNewContext(source, context);

  const send = (message) => new Promise((resolve) => {
    listener(message, {}, resolve);
  });
  return { calls, localValues, send };
}

const scanMessage = {
  type: "DLP_SCAN",
  payload: {
    content: "sensitive text",
    channel: "browser",
    destination: "example.com",
    filename: null,
  },
};

test("sign-in uses Supabase password grant, then sends bearer token without body user id", async () => {
  const extension = createExtension();
  const auth = await extension.send({
    type: "DLP_SIGN_IN",
    email: "member@example.com",
    password: "not-persisted",
  });
  assert.equal(auth.authenticated, true);
  assert.equal(extension.localValues.authSession.access_token, "short-lived-access-token");
  assert.equal(extension.localValues.authSession.refresh_token, "refresh-token");
  assert.equal(extension.localValues.authSession.password, undefined);

  const result = await extension.send(scanMessage);
  assert.equal(result.decision, "allow");
  const request = extension.calls.find(({ url }) => url.endsWith("/api/scan"));
  assert.equal(request.init.headers.Authorization, "Bearer short-lived-access-token");
  const body = JSON.parse(request.init.body);
  assert.equal(body.org_id, "org-to-check");
  assert.equal(Object.hasOwn(body, "user_id"), false);
});

test("expired session refreshes before scanning", async () => {
  const extension = createExtension();
  extension.localValues.authSession = {
    access_token: "expired-token",
    refresh_token: "old-refresh-token",
    expires_at: Date.now() - 1,
  };

  const result = await extension.send(scanMessage);
  assert.equal(result.decision, "allow");
  const request = extension.calls.find(({ url }) => url.endsWith("/api/scan"));
  assert.equal(request.init.headers.Authorization, "Bearer refreshed-access-token");
  assert.equal(extension.localValues.authSession.refresh_token, "rotated-refresh-token");
});

test("failed authentication blocks and does not request a scan", async () => {
  const extension = createExtension({ authStatus: 401 });
  const auth = await extension.send({
    type: "DLP_SIGN_IN",
    email: "member@example.com",
    password: "wrong-password",
  });
  assert.equal(auth.authenticated, false);

  const result = await extension.send(scanMessage);
  assert.equal(result.decision, "block");
  assert.equal(extension.calls.some(({ url }) => url.endsWith("/api/scan")), false);
});

test("backend scan rejection blocks", async () => {
  const extension = createExtension({ scanStatus: 403 });
  extension.localValues.authSession = {
    access_token: "short-lived-access-token",
    refresh_token: "refresh-token",
    expires_at: Date.now() + 60_000,
  };

  const result = await extension.send(scanMessage);
  assert.equal(result.decision, "block");
});

test("sign-in rejects a service-role key", async () => {
  const extension = createExtension({ supabasePublishableKey: "sb_secret_server_key" });
  const result = await extension.send({
    type: "DLP_SIGN_IN",
    email: "member@example.com",
    password: "password",
  });
  assert.equal(result.authenticated, false);
  assert.equal(extension.calls.length, 0);
});

test("malformed scan response blocks", async () => {
  const extension = createExtension({
    scanResult: {
      findings: [{}],
      decision: "allow",
      matched_policy_id: null,
      reason: "No policy matched",
    },
  });
  extension.localValues.authSession = {
    access_token: "short-lived-access-token",
    refresh_token: "refresh-token",
    expires_at: Date.now() + 60_000,
  };

  const result = await extension.send(scanMessage);
  assert.equal(result.decision, "block");
});

test("refuses to send the bearer token to a non-HTTPS remote backend", async () => {
  const extension = createExtension({ backendUrl: "http://backend.example" });
  extension.localValues.authSession = {
    access_token: "short-lived-access-token",
    refresh_token: "refresh-token",
    expires_at: Date.now() + 60_000,
  };

  const result = await extension.send(scanMessage);
  assert.equal(result.decision, "block");
  assert.equal(extension.calls.some(({ url }) => url.includes("backend.example/api/scan")), false);
});
