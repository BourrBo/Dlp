const fields = ["backendUrl", "orgId", "userId"];

async function load() {
  const stored = await chrome.storage.sync.get([...fields, "failClosed"]);
  for (const f of fields) {
    if (stored[f]) document.getElementById(f).value = stored[f];
  }
  document.getElementById("failClosed").checked = !!stored.failClosed;
}

document.getElementById("save").addEventListener("click", async () => {
  const values = {};
  for (const f of fields) values[f] = document.getElementById(f).value.trim();
  values.failClosed = document.getElementById("failClosed").checked;
  await chrome.storage.sync.set(values);
  setStatus("Saved.", "#2f9e6d");
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

load();
