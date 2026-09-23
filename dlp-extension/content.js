/**
 * Runs on every page. Two interception points:
 *   1. paste events into inputs/textareas/contenteditable elements
 *   2. file selection on <input type="file">
 *
 * Both are sent to the background worker's DLP_SCAN handler. A BLOCK
 * decision stops the content from ever landing in the page; WARN asks
 * for confirmation; ALLOW/LOG pass through silently.
 *
 * Scope limit (documented, not hidden): file scanning only reads
 * text-like files (txt/csv/json/md/log). Binary files (images, PDFs,
 * zips) are not content-scanned in v1 — see architecture doc §8.
 */

const MIN_SCAN_LENGTH = 8;
const TEXT_LIKE_EXTENSIONS = [".txt", ".csv", ".json", ".md", ".log"];

function isEditable(el) {
  if (!el) return false;
  const tag = el.tagName;
  return tag === "TEXTAREA" || tag === "INPUT" || el.isContentEditable;
}

function insertTextAtCursor(el, text) {
  if (el.isContentEditable) {
    document.execCommand("insertText", false, text);
    return;
  }
  const start = el.selectionStart ?? el.value.length;
  const end = el.selectionEnd ?? el.value.length;
  el.value = el.value.slice(0, start) + text + el.value.slice(end);
  el.selectionStart = el.selectionEnd = start + text.length;
  el.dispatchEvent(new Event("input", { bubbles: true }));
}

function requestScan(payload) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "DLP_SCAN", payload }, (response) => {
      resolve(response ?? { decision: "allow", findings: [], reason: "No response from extension" });
    });
  });
}

// --- paste interception ---------------------------------------------------

document.addEventListener(
  "paste",
  async (event) => {
    const el = event.target;
    if (!isEditable(el)) return;

    const text = event.clipboardData?.getData("text/plain") ?? "";
    if (text.length < MIN_SCAN_LENGTH) return; // too short to be worth a round trip

    event.preventDefault();
    event.stopPropagation();

    const result = await requestScan({
      content: text,
      channel: "browser",
      destination: window.location.hostname,
    });

    if (result.decision === "block") {
      showBanner(`Paste blocked — ${result.reason}`, "block");
      return;
    }
    if (result.decision === "warn") {
      const proceed = window.confirm(
        `This paste may contain sensitive data (${result.reason}). Paste anyway?`
      );
      if (!proceed) {
        showBanner("Paste cancelled", "warn");
        return;
      }
    }
    insertTextAtCursor(el, text);
  },
  true // capture phase — intercept before the page's own handlers
);

// --- file upload interception ----------------------------------------------

document.addEventListener(
  "change",
  async (event) => {
    const el = event.target;
    if (el.tagName !== "INPUT" || el.type !== "file" || !el.files?.length) return;

    for (const file of Array.from(el.files)) {
      const isTextLike = TEXT_LIKE_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext));
      if (!isTextLike) continue; // binary files: not content-scanned in v1

      const text = await file.text();
      if (text.length < MIN_SCAN_LENGTH) continue;

      const result = await requestScan({
        content: text,
        channel: "browser",
        destination: window.location.hostname,
        filename: file.name,
      });

      if (result.decision === "block") {
        el.value = ""; // clear the selection
        showBanner(`Upload blocked — "${file.name}": ${result.reason}`, "block");
        return;
      }
      if (result.decision === "warn") {
        const proceed = window.confirm(`"${file.name}" may contain sensitive data (${result.reason}). Upload anyway?`);
        if (!proceed) {
          el.value = "";
          showBanner("Upload cancelled", "warn");
          return;
        }
      }
    }
  },
  true
);

// --- banner UI ---------------------------------------------------------

function showBanner(message, kind) {
  const colors = { block: "#e0413a", warn: "#d99a1f", allow: "#2f9e6d" };
  const el = document.createElement("div");
  el.textContent = `DLP Guard: ${message}`;
  Object.assign(el.style, {
    position: "fixed",
    top: "16px",
    right: "16px",
    zIndex: 2147483647,
    background: colors[kind] ?? "#333",
    color: "#fff",
    padding: "10px 16px",
    borderRadius: "8px",
    fontFamily: "system-ui, sans-serif",
    fontSize: "13px",
    boxShadow: "0 4px 12px rgba(0,0,0,0.25)",
    maxWidth: "320px",
  });
  document.documentElement.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}
