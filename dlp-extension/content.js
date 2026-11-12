/**
 * DLP Guard browser capture: clipboard paste, native file selection, and
 * file drag-and-drop. Small text files use the synchronous scan route; binary
 * and larger files stream through the extension worker to durable extraction.
 */

const MIN_SCAN_LENGTH = 8;
const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MAX_INLINE_BYTES = 5 * 1024 * 1024;
const MAX_INLINE_TEXT_CHARS = 5 * 1024 * 1024;
const TEXT_LIKE_EXTENSIONS = [".txt", ".csv", ".json", ".md", ".log"];
const replayedChanges = new WeakSet();
const replayedDrops = new WeakSet();
const replayedSubmits = new WeakSet();
let activeBanner = null;
let activeBannerTimer = null;
let cachedFailClosed = true;

try {
  chrome.runtime.sendMessage({ type: "DLP_GET_CONFIG" }, (config) => {
    if (!chrome.runtime.lastError && typeof config?.failClosed === "boolean") {
      cachedFailClosed = config.failClosed;
    }
  });
} catch {
  // Keep the fail-closed default when this page has a stale extension context.
}

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
    const inactive = (reason) => resolve({ decision: cachedFailClosed ? "block" : "allow", findings: [], reason, inactive: true, unavailable: true });
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

function normalizedDestination() {
  return DlpExtension.normalizeHost(window.location.hostname);
}

function isOversizedText(text) {
  return text.length > MAX_INLINE_TEXT_CHARS || new Blob([text]).size > MAX_INLINE_TEXT_CHARS;
}

function warnInactive(result) {
  showBanner(`Not scanned (${result.reason}). Refresh this page to re-enable DLP Guard.`, "warn");
}

function warnUnavailable(result) {
  if (result.unavailable) showBanner(`DLP did not scan this content: ${result.reason}`, result.decision === "block" ? "block" : "warn");
}

function requestFileScan(file) {
  return new Promise((resolve) => {
    let complete = false;
    let nextAck = null;
    const unavailable = (reason) => ({ decision: cachedFailClosed ? "block" : "allow", findings: [], reason, unavailable: true });
    let port;
    try {
      port = chrome.runtime.connect({ name: "DLP_FILE_SCAN" });
    } catch (err) {
      resolve(unavailable(err.message || "DLP extension context is unavailable."));
      return;
    }

    port.onMessage.addListener((message) => {
      if (message.type === "READY") {
        void (async () => {
          try {
            let sequence = 0;
            for (let offset = 0; offset < file.size; offset += message.chunkBytes) {
              const bytes = new Uint8Array(await file.slice(offset, offset + message.chunkBytes).arrayBuffer());
              let binary = "";
              for (let index = 0; index < bytes.length; index += 0x8000) {
                binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
              }
              const ack = new Promise((ackResolve, ackReject) => {
                const timer = setTimeout(() => ackReject(new Error("Timed out while sending file data to the scanner.")), 10000);
                nextAck = { sequence, resolve: ackResolve, reject: ackReject, timer };
              });
              port.postMessage({ type: "CHUNK", sequence, data: btoa(binary) });
              await ack;
              clearTimeout(nextAck?.timer);
              nextAck = null;
              sequence += 1;
            }
            port.postMessage({ type: "FINISH" });
          } catch (error) {
            try { port.disconnect(); } catch { /* extension context closed */ }
            if (!complete) {
              complete = true;
              resolve(unavailable(error.message || "File transfer failed."));
            }
          }
        })();
      } else if (message.type === "ACK" && nextAck?.sequence === message.sequence) {
        clearTimeout(nextAck.timer);
        nextAck.resolve();
      } else if (message.type === "PROGRESS" || message.type === "JOB") {
        const phase = message.phase || message.status || "queued";
        showBanner(`DLP scanning ${file.name}: ${phase} ${message.progress ?? 0}%`, "warn");
      } else if (message.type === "DONE") {
        complete = true;
        resolve(message.result);
        port.disconnect();
      }
    });

    port.onDisconnect.addListener(() => {
      if (!complete) {
        complete = true;
        clearTimeout(nextAck?.timer);
        nextAck?.reject(new Error("DLP extension disconnected during file scanning."));
        resolve(unavailable("DLP extension disconnected during file scanning."));
      }
    });
    port.postMessage({
      type: "START",
      filename: file.name,
      size: file.size,
      contentType: file.type,
      destination: normalizedDestination(),
    });
  });
}

function onPaste(event) {
  const el = event.target;
  if (!isEditable(el)) return;

  const text = event.clipboardData?.getData("text/plain") ?? "";
  if (text.length < MIN_SCAN_LENGTH) return;

  event.preventDefault();
  event.stopImmediatePropagation();

  if (isOversizedText(text)) {
    const reason = "Paste was too large to inspect inline.";
    showBanner(`${reason} ${cachedFailClosed ? "Paste blocked." : "Paste allowed by fail-open setting."}`, cachedFailClosed ? "block" : "warn");
    if (!cachedFailClosed) insertTextAtCursor(el, text);
    return;
  }

  void (async () => {
    const result = await requestScan({
      content: text,
      channel: "browser",
      destination: normalizedDestination(),
    });

    if (result.inactive) warnInactive(result);
    warnUnavailable(result);
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
    if (file.size > MAX_FILE_BYTES) {
      const reason = `"${file.name}" exceeds the 25 MiB scan limit.`;
      showBanner(`${reason} ${cachedFailClosed ? "Upload blocked." : "Upload allowed by fail-open setting."}`, cachedFailClosed ? "block" : "warn");
      if (cachedFailClosed) return { allowed: false, reason };
      continue;
    }

    let result;
    if (isTextLike(file) && file.size <= MAX_INLINE_BYTES) {
      let text;
      try {
        text = await file.text();
      } catch {
        const reason = `"${file.name}" could not be read for scanning.`;
        showBanner(`${reason} ${cachedFailClosed ? "Upload blocked." : "Upload allowed by fail-open setting."}`, cachedFailClosed ? "block" : "warn");
        if (cachedFailClosed) return { allowed: false, reason };
        continue;
      }
      if (text.length < MIN_SCAN_LENGTH) continue;
      result = await requestScan({ content: text, channel: "browser", destination: normalizedDestination(), filename: file.name });
    } else {
      result = await requestFileScan(file);
    }

    if (result.inactive) warnInactive(result);
    warnUnavailable(result);
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
  if (DlpExtension.hasDirectoryItems(transfer?.items)) {
    if (!cachedFailClosed) {
      showBanner("Folder drops were not scanned and are allowed by the fail-open setting.", "warn");
      return;
    }
    event.preventDefault();
    event.stopImmediatePropagation();
    showBanner("Folder drop blocked because folder contents cannot be scanned safely yet.", "block");
    return;
  }
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

function formText(form) {
  const values = [];
  for (const field of form.querySelectorAll("textarea, input[type='text'], input[type='search'], input[type='email'], input:not([type]), [contenteditable='true']")) {
    if (field.disabled || field.readOnly) continue;
    const value = field.isContentEditable ? field.innerText : field.value;
    if (typeof value === "string" && value.trim().length >= MIN_SCAN_LENGTH) values.push(value.trim());
  }
  return values.join("\n");
}

async function onSubmit(event) {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || replayedSubmits.has(form)) return;
  const content = formText(form);
  if (!content) return;

  event.preventDefault();
  event.stopImmediatePropagation();
  if (isOversizedText(content)) {
    showBanner(`Submission is too large to inspect inline. ${cachedFailClosed ? "Blocked." : "Allowed by fail-open setting."}`, cachedFailClosed ? "block" : "warn");
    if (!cachedFailClosed) {
      replayedSubmits.add(form);
      if (typeof form.requestSubmit === "function") form.requestSubmit(event.submitter ?? undefined);
      else form.submit();
      setTimeout(() => replayedSubmits.delete(form), 0);
    }
    return;
  }
  const result = await requestScan({ content, channel: "browser", destination: normalizedDestination() });
  if (result.inactive) warnInactive(result);
  warnUnavailable(result);
  if (result.decision === "block") {
    showBanner(`Submission blocked — ${result.reason}`, "block");
    return;
  }
  if (result.decision === "warn") {
    const proceed = window.confirm(`This submission may contain sensitive data (${result.reason}). Continue?`);
    if (!proceed) {
      showBanner("Submission cancelled", "warn");
      return;
    }
  }

  try {
    replayedSubmits.add(form);
    if (typeof form.requestSubmit === "function") form.requestSubmit(event.submitter ?? undefined);
    else form.submit();
  } catch {
    replayedSubmits.delete(form);
    showBanner("Content was scanned, but this page could not safely resume submission.", "warn");
  }
  setTimeout(() => replayedSubmits.delete(form), 0);
}

function onDragOver(event) {
  if (Array.from(event.dataTransfer?.types ?? []).includes("Files")) event.preventDefault();
}

document.addEventListener("paste", onPaste, true);
document.addEventListener("change", onFileChange, true);
document.addEventListener("drop", onDrop, true);
document.addEventListener("dragover", onDragOver, true);
document.addEventListener("submit", onSubmit, true);

function showBanner(message, kind) {
  const colors = { block: "#e0413a", warn: "#d99a1f", allow: "#2f9e6d" };
  if (!activeBanner?.isConnected) {
    activeBanner = document.createElement("div");
    Object.assign(activeBanner.style, {
      position: "fixed",
      top: "16px",
      right: "16px",
      zIndex: 2147483647,
      color: "#fff",
      padding: "10px 16px",
      borderRadius: "8px",
      fontFamily: "system-ui, sans-serif",
      fontSize: "13px",
      boxShadow: "0 4px 12px rgba(0,0,0,0.25)",
      maxWidth: "320px",
    });
    document.documentElement.appendChild(activeBanner);
  }
  activeBanner.textContent = `DLP Guard: ${message}`;
  activeBanner.style.background = colors[kind] ?? "#333";
  clearTimeout(activeBannerTimer);
  activeBannerTimer = setTimeout(() => {
    activeBanner?.remove();
    activeBanner = null;
  }, 5000);
}
