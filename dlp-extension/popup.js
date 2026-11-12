async function init() {
  const config = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "DLP_GET_CONFIG" }, resolve);
  });
  const enabled = document.getElementById("enabled");
  enabled.checked = config?.enabled ?? true;
  enabled.disabled = (config?.managedKeys ?? []).includes("enabled");
  if (enabled.disabled) enabled.title = "Protection is managed by your administrator.";

  const { recentEvents = [] } = await chrome.storage.local.get("recentEvents");
  const list = document.getElementById("events");

  if (recentEvents.length === 0) {
    list.innerHTML = '<li class="empty">No activity yet. Paste or upload something on a page to see it here.</li>';
    return;
  }

  list.innerHTML = recentEvents
    .map((e) => {
      const time = new Date(e.at).toLocaleTimeString();
      return `<li><span class="decision ${e.decision}">${e.decision}</span>${e.destination ?? "—"} · ${time}</li>`;
    })
    .join("");
}

document.getElementById("enabled").addEventListener("change", async (e) => {
  await chrome.storage.local.set({ enabled: e.target.checked });
});

document.getElementById("openOptions").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

init();
