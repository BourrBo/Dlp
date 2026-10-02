/**
 * DLP Guard browser capture: clipboard paste, native file selection, and
 * file drag-and-drop. Binary formats remain out of scope until the backend
 * extraction endpoint is available.
 */

const MIN_SCAN_LENGTH = 8;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const TEXT_LIKE_EXTENSIONS = [".txt", ".csv", ".json", ".md", ".log"];
const replayedChanges = new WeakSet();
const replayedDrops = new WeakSet();

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
    const inactive = (reason) => resolve({ decision: "allow", findings: [], reason, inactive: true });
    try {
      chrome.runtime.sendMessage({ type: "DLP_SCAN", payload }, (response) => {
        if (chrome.runtime.lastError || !response) {
          inactive(chrome.runtime.lastError?.message ?? "No response from extension");
          return;
        }
        resolve(response);
      });
    } catch (err) {
      inactive(err.message || "Extension context invalidated");
    }
  });
}

function warnInactive(result) {
  showBanner(`Not scanned (${result.reason}). Refresh this page to re-enable DLP Guard.`, "warn");
}

function onPaste(event) {
  const el = event.target;
  if (!isEditable(el)) return;

  const text = event.clipboardData?.getData("text/plain") ?? "";
  if (text.length < MIN_SCAN_LENGTH) return;

  event.preventDefault();
  event.stopImmediatePropagation();

  void (async () => {
    const result = await requestScan({
      content: text,
      channel: "browser",
      destination: window.location.hostname,
    });

    if (result.inactive) warnInactive(result);
    if (result.decision === "block") {
      showBanner(`Paste blocked — ${result.reason}`, "block");
      return;
    }
    if (result.decision === "warn") {
      const proceed = window.confirm(`This paste may contain sensitive data (${result.reason}). Paste anyway?`);
      if (!proceed) {
        showBanner("Paste cancelled", "warn");
        return;
      }
    }
    insertTextAtCursor(el, text);
  })();
}

function isTextLike(file) {
  return TEXT_LIKE_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext));
}

async function scanFiles(files) {
  for (const file of files) {
    if (!isTextLike(file)) {
      showBanner(`Not scanned: "${file.name}" is not a supported text file.`, "warn");
      continue;
    }
    if (file.size > MAX_FILE_BYTES) {
      return { allowed: false, reason: `"${file.name}" exceeds the 5 MB scan limit.` };
    }

    let text;
    try {
      text = await file.text();
    } catch {
      return { allowed: false, reason: `"${file.name}" could not be read for scanning.` };
    }
    if (text.length < MIN_SCAN_LENGTH) continue;

    const result = await requestScan({
      content: text,
      channel: "browser",
      destination: window.location.hostname,
      filename: file.name,
    });

    if (result.inactive) warnInactive(result);
    if (result.decision === "block") {
      return { allowed: false, reason: `"${file.name}" was blocked: ${result.reason}` };
    }
    if (result.decision === "warn") {
      const proceed = window.confirm(`"${file.name}" may contain sensitive data (${result.reason}). Upload anyway?`);
      if (!proceed) return { allowed: false, reason: "Upload cancelled." };
    }
  }
  return { allowed: true };
}

function makeFileList(files) {
  const transfer = new DataTransfer();
  for (const file of files) transfer.items.add(file);
  return transfer;
}

async function onFileChange(event) {
  if (replayedChanges.has(event)) return;
  const input = event.target;
  if (!(input instanceof HTMLInputElement) || input.type !== "file" || !input.files?.length) return;

  // Stop page handlers and clear the selection before awaiting the scan, so
  // the page cannot submit the files while the decision is still pending.
  event.preventDefault();
  event.stopImmediatePropagation();
  const files = Array.from(input.files);
  input.value = "";

  const result = await scanFiles(files);
  if (!result.allowed) {
    showBanner(result.reason, "block");
    return;
  }

  try {
    input.files = makeFileList(files).files;
    const replay = new Event("change", { bubbles: true });
    replayedChanges.add(replay);
    input.dispatchEvent(replay);
  } catch {
    input.value = "";
    showBanner("Files were scanned but this browser could not safely resume the upload.", "warn");
  }
}

async function onDrop(event) {
  if (replayedDrops.has(event)) return;
  const transfer = event.dataTransfer;
  if (!transfer?.files?.length) return;

  event.preventDefault();
  event.stopImmediatePropagation();
  const files = Array.from(transfer.files);
  const result = await scanFiles(files);
  if (!result.allowed) {
    showBanner(result.reason, "block");
    return;
  }

  try {
    const replay = new DragEvent("drop", {
      bubbles: true,
      cancelable: true,
      clientX: event.clientX,
      clientY: event.clientY,
      screenX: event.screenX,
      screenY: event.screenY,
      dataTransfer: makeFileList(files),
    });
    replayedDrops.add(replay);
    event.target.dispatchEvent(replay);
  } catch {
    showBanner("Files were scanned but this browser could not safely resume the drop.", "warn");
  }
}

function onDragOver(event) {
  if (Array.from(event.dataTransfer?.types ?? []).includes("Files")) event.preventDefault();
}

document.addEventListener("paste", onPaste, true);
document.addEventListener("change", onFileChange, true);
document.addEventListener("drop", onDrop, true);
document.addEventListener("dragover", onDragOver, true);

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
