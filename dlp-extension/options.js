const fields = ["backendUrl", "supabaseUrl", "supabasePublishableKey", "orgId"];

async function load() {
  const stored = await chrome.storage.sync.get(fields);
  for (const f of fields) {
    if (stored[f]) document.getElementById(f).value = stored[f];
  }
  await updateAuthStatus();
}

async function saveSettings() {
  const values = {};
  for (const f of fields) values[f] = document.getElementById(f).value.trim();
  const result = await chrome.runtime.sendMessage({ type: "DLP_SAVE_CONFIG", config: values });
  if (result?.error) throw new Error(result.error);
}

document.getElementById("save").addEventListener("click", async () => {
  try {
    await saveSettings();
  } catch (err) {
    setStatus(`Could not save settings: ${err.message}`, "#e0413a");
    return;
  }
  setStatus("Saved.", "#2f9e6d");
});

document.getElementById("signIn").addEventListener("click", async () => {
  setStatus("Signing in…", "#555");
  try {
    await saveSettings();
    const result = await chrome.runtime.sendMessage({
      type: "DLP_SIGN_IN",
      email: document.getElementById("email").value.trim(),
      password: document.getElementById("password").value,
    });
    if (!result?.authenticated) throw new Error(result?.error ?? "Authentication failed.");
    document.getElementById("password").value = "";
    setStatus(`Signed in${result.email ? ` as ${result.email}` : ""}.`, "#2f9e6d");
  } catch (err) {
    setStatus(err.message, "#e0413a");
  }
});

document.getElementById("signOut").addEventListener("click", async () => {
  try {
    await chrome.runtime.sendMessage({ type: "DLP_SIGN_OUT" });
    document.getElementById("password").value = "";
    setStatus("Signed out.", "#555");
  } catch (err) {
    setStatus(`Could not sign out: ${err.message}`, "#e0413a");
  }
});

document.getElementById("test").addEventListener("click", async () => {
  const backendUrl = document.getElementById("backendUrl").value.trim() || "http://localhost:8000";
  setStatus("Testing…", "#555");
  try {
    const res = await fetch(`${backendUrl}/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    setStatus(`Connected — backend says: ${JSON.stringify(body)}`, "#2f9e6d");
  } catch (err) {
    setStatus(`Could not reach backend: ${err.message}`, "#e0413a");
  }
});

function setStatus(text, color) {
  const el = document.getElementById("status");
  el.textContent = text;
  el.style.color = color;
}

async function updateAuthStatus() {
  try {
    const state = await chrome.runtime.sendMessage({ type: "DLP_AUTH_STATE" });
    if (state?.authenticated) {
      setStatus(`Signed in${state.email ? ` as ${state.email}` : ""}.`, "#2f9e6d");
    }
  } catch {
    setStatus("Could not read extension authentication state.", "#e0413a");
  }
}

load();
