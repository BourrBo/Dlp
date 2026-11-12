/**
 * Optional personal sign-in (Supabase email/password) used only when no scoped
 * API key is configured. Tokens live in extension-local storage, restricted to
 * trusted contexts, and are used by the service worker alone.
 */
(function (root) {
  const SESSION_KEY = "authSession";
  let refreshInProgress;

  function ready() {
    try {
      return Promise.resolve(chrome.storage.local.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" })).catch(() => undefined);
    } catch {
      return Promise.resolve();
    }
  }

  function isPublicSupabaseKey(key) {
    if (typeof key !== "string" || !key) return false;
    if (key.startsWith("sb_publishable_")) return true;
    try {
      return JSON.parse(atob(key.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).role === "anon";
    } catch {
      return false;
    }
  }

  function secureBaseUrl(value) {
    const url = new URL(value);
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.protocol !== "https:" && !local) throw new Error("Supabase URL must use HTTPS.");
    if (url.username || url.password) throw new Error("Supabase URL must not contain credentials.");
    return url.origin;
  }

  function isValidSession(body) {
    return Boolean(body) && typeof body === "object" &&
      typeof body.access_token === "string" && body.access_token.length > 0 &&
      typeof body.refresh_token === "string" && body.refresh_token.length > 0 &&
      Number.isFinite(body.expires_in) && body.expires_in > 0;
  }

  function isConfigured(config) {
    return Boolean(config && config.supabaseUrl && isPublicSupabaseKey(config.supabasePublishableKey));
  }

  async function requestToken(config, grantType, payload) {
    if (!isConfigured(config)) throw new Error("Configure the Supabase URL and publishable key first.");
    const response = await fetch(`${secureBaseUrl(config.supabaseUrl)}/auth/v1/token?grant_type=${grantType}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: config.supabasePublishableKey },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(response.status === 400 || response.status === 401
        ? "Sign-in failed. Check your credentials."
        : `Authentication service returned HTTP ${response.status}.`);
    }
    const body = await response.json();
    if (!isValidSession(body)) throw new Error("The authentication service returned an invalid session.");
    return {
      access_token: body.access_token,
      refresh_token: body.refresh_token,
      expires_at: Date.now() + body.expires_in * 1000,
      email: typeof body.user?.email === "string" ? body.user.email : "",
    };
  }

  async function signIn(config, email, password) {
    if (typeof email !== "string" || !email.trim() || typeof password !== "string" || !password) {
      throw new Error("Enter your account email and password.");
    }
    const session = await requestToken(config, "password", { email: email.trim(), password });
    await ready();
    await chrome.storage.local.set({ [SESSION_KEY]: session });
    return { authenticated: true, email: session.email };
  }

  async function signOut() {
    await ready();
    await chrome.storage.local.remove(SESSION_KEY);
    return { authenticated: false, email: "" };
  }

  async function getAuthState() {
    const stored = await chrome.storage.local.get(SESSION_KEY);
    const session = stored[SESSION_KEY];
    return { authenticated: Boolean(session?.refresh_token), email: session?.email ?? "" };
  }

  async function getAccessToken(config) {
    await ready();
    const session = (await chrome.storage.local.get(SESSION_KEY))[SESSION_KEY];
    if (!session?.access_token || !session?.refresh_token) {
      throw new Error("Sign in from the extension settings, or ask your administrator for an API key.");
    }
    if (session.expires_at > Date.now() + 30000) return session.access_token;
    if (!refreshInProgress) {
      refreshInProgress = requestToken(config, "refresh_token", { refresh_token: session.refresh_token })
        .then(async (refreshed) => {
          await chrome.storage.local.set({ [SESSION_KEY]: refreshed });
          return refreshed;
        })
        .finally(() => { refreshInProgress = undefined; });
    }
    try {
      return (await refreshInProgress).access_token;
    } catch (error) {
      await signOut();
      throw error;
    }
  }

  root.DlpPersonalAuth = { isConfigured, isPublicSupabaseKey, signIn, signOut, getAuthState, getAccessToken };
})(globalThis);
