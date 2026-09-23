async function init() {
  const { enabled = true } = await chrome.storage.sync.get("enabled");
  document.getElementById("enabled").checked = enabled;

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
  await chrome.storage.sync.set({ enabled: e.target.checked });
});

document.getElementById("openOptions").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

init();
