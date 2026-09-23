/**
 * Background service worker. Content scripts never call the backend
 * directly — they message this worker, which reads config from
 * chrome.storage.sync and makes the /api/scan request. Keeps the fetch
 * (and any future auth header) in one place.
 */

const DEFAULT_CONFIG = {
  backendUrl: "http://localhost:8000",
  orgId: "",
  userId: "",
  enabled: true,
};

async function getConfig() {
  const stored = await chrome.storage.sync.get(DEFAULT_CONFIG);
  return { ...DEFAULT_CONFIG, ...stored };
}

async function scan({ content, channel, destination, filename }) {
  const config = await getConfig();

  if (!config.enabled) {
    return { decision: "allow", findings: [], reason: "Protection disabled" };
  }
  if (!config.orgId || !config.userId) {
    return { decision: "allow", findings: [], reason: "Extension not configured — set org/user ID in options" };
  }

  try {
    const res = await fetch(`${config.backendUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        org_id: config.orgId,
        user_id: config.userId,
        channel,
        destination,
        content,
        filename: filename ?? null,
      }),
    });
    if (!res.ok) {
      throw new Error(`Backend returned ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    // Backend unreachable: fail open (allow) rather than breaking every page.
    // Logged locally so it's visible in the popup's recent-activity list.
    await logLocalEvent({ decision: "allow", reason: `Backend unreachable: ${err.message}`, destination, channel });
    return { decision: "allow", findings: [], reason: `Backend unreachable: ${err.message}` };
  }
}

async function logLocalEvent(entry) {
  const { recentEvents = [] } = await chrome.storage.local.get("recentEvents");
  const updated = [{ ...entry, at: Date.now() }, ...recentEvents].slice(0, 25);
  await chrome.storage.local.set({ recentEvents: updated });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type !== "DLP_SCAN") return false;

  scan(message.payload)
    .then((result) => {
      logLocalEvent({
        decision: result.decision,
        reason: result.reason,
        destination: message.payload.destination,
        channel: message.payload.channel,
      });
      sendResponse(result);
    })
    .catch((err) => sendResponse({ decision: "allow", findings: [], reason: `Extension error: ${err.message}` }));

  return true; // keep the message channel open for the async response
});
