const $ = (id) => document.getElementById(id);
const fields = ["backendUrl", "aiSites", "enabled", "failClosed", "supabaseUrl", "supabasePublishableKey"];

function setStatus(message, kind = "info") {
  const status = $("status");
  status.textContent = message;
  status.style.color = kind === "error" ? "#b42318" : kind === "success" ? "#067647" : "#344054";
}

function send(message) {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}

async function load() {
  const config = await send({ type: "DLP_GET_CONFIG" });
  const { backendUrl = "http://localhost:8000", aiSites = DlpExtension.DEFAULT_AI_SITES, enabled = true, failClosed = false, managedKeys = [] } = config;
  const { apiKey: localKey } = await chrome.storage.local.get("apiKey");
  $("backendUrl").value = backendUrl;
  const local = await chrome.storage.local.get(["supabaseUrl", "supabasePublishableKey"]);
  $("supabaseUrl").value = config.supabaseUrl || local.supabaseUrl || "";
  $("supabasePublishableKey").value = local.supabasePublishableKey || "";
  $("signedInAs").textContent = config.signedInAs ? `Signed in as ${config.signedInAs}` : "Not signed in.";
  if (config.usingApiKey) $("signedInAs").textContent += " An API key is configured and takes precedence.";
  $("aiSites").value = aiSites.join("\n");
  $("enabled").checked = enabled;
  $("failClosed").checked = failClosed;
  $("apiKey").placeholder = config.configured
    ? managedKeys.includes("apiKey") ? "Configured by your administrator" : "A local key is saved; enter a new key to replace it"
    : "Enter a scoped DLP API key";
  $("keyHint").textContent = config.configured
    ? managedKeys.includes("apiKey") ? "The administrator-managed key is used without exposing it to page scripts." : "A local API key is saved in this browser profile and is not synced."
    : "A key provided by your administrator is preferred. A local key is stored in this browser profile and is not synced.";

  for (const field of fields) {
    if (managedKeys.includes(field)) $(field).disabled = true;
  }
  if (managedKeys.includes("apiKey")) {
    $("apiKey").disabled = true;
    $("clearKey").disabled = true;
  }
  if (managedKeys.length) $("managedNotice").hidden = false;
  if (localKey && !config.configured) setStatus("A local API key is available.");
}

$("save").addEventListener("click", async () => {
  const backendUrl = $("backendUrl").value.trim();
  let url;
  try {
    url = new URL(backendUrl);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      throw new Error("Enter only the backend origin, for example https://dlp-api.example.com");
    }
  } catch (err) {
    setStatus(err.message || "Enter a valid backend URL.", "error");
    return;
  }

  const apiKey = $("apiKey").value.trim();
  const aiSites = DlpExtension.normalizeSites($("aiSites").value.split(/[\r\n,]+/));
  const stored = { backendUrl: url.origin, aiSites, enabled: $("enabled").checked, failClosed: $("failClosed").checked };
  if (apiKey) stored.apiKey = apiKey;
  for (const id of ["supabaseUrl", "supabasePublishableKey"]) {
    if (!$(id).disabled) stored[id] = $(id).value.trim();
  }
  await chrome.storage.local.set(stored);
  $("apiKey").value = "";
  setStatus("Settings saved to this browser profile. The API key was not synced.", "success");
  await load();
});

$("clearKey").addEventListener("click", async () => {
  await chrome.storage.local.remove("apiKey");
  $("apiKey").value = "";
  setStatus("Local API key cleared.", "success");
  await load();
});

$("test").addEventListener("click", async () => {
  setStatus("Checking connection…");
  const result = await send({ type: "DLP_TEST_CONNECTION" });
  if (result?.error) setStatus(`Connection failed: ${result.error}`, "error");
  else setStatus(`Backend is reachable (${JSON.stringify(result)}). Scan authentication still depends on the configured API key.`, "success");
});

$("signIn").addEventListener("click", async () => {
  setStatus("Signing in…");
  await chrome.storage.local.set({
    supabaseUrl: $("supabaseUrl").value.trim(),
    supabasePublishableKey: $("supabasePublishableKey").value.trim(),
  });
  const result = await send({ type: "DLP_SIGN_IN", email: $("email").value, password: $("password").value });
  $("password").value = "";
  if (result?.error) setStatus(result.error, "error");
  else setStatus(`Signed in as ${result.email}.`, "success");
  await load();
});

$("signOut").addEventListener("click", async () => {
  await send({ type: "DLP_SIGN_OUT" });
  setStatus("Signed out.", "success");
  await load();
});

void load();
