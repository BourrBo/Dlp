(function (root) {
  "use strict";

  const DEFAULT_AI_SITES = [
    "chatgpt.com",
    "chat.openai.com",
    "gemini.google.com",
    "claude.ai",
    "copilot.microsoft.com",
    "perplexity.ai",
  ];

  function normalizeHost(value) {
    if (typeof value !== "string" || !value.trim()) return "";
    let candidate = value.trim().toLowerCase();
    try {
      candidate = new URL(candidate.includes("://") ? candidate : `https://${candidate}`).hostname;
    } catch {
      return "";
    }
    return candidate.replace(/^www\./, "").replace(/\.$/, "");
  }

  function normalizeSites(values) {
    if (!Array.isArray(values)) return DEFAULT_AI_SITES.slice();
    return [...new Set(values.map(normalizeHost).filter(Boolean))];
  }

  function isProtectedDestination(host, sites) {
    const normalized = normalizeHost(host);
    const allowed = normalizeSites(sites);
    return Boolean(normalized && allowed.some((site) => normalized === site || normalized.endsWith(`.${site}`)));
  }

  function hasDirectoryItems(items) {
    if (!items || typeof items[Symbol.iterator] !== "function") return false;
    for (const item of items) {
      if (item?.kind !== "file" || typeof item.webkitGetAsEntry !== "function") continue;
      try {
        if (item.webkitGetAsEntry()?.isDirectory) return true;
      } catch {
        // Treat an unreadable file entry conservatively; the folder cannot be inspected.
        return true;
      }
    }
    return false;
  }

  const api = { DEFAULT_AI_SITES, normalizeHost, normalizeSites, isProtectedDestination, hasDirectoryItems };
  root.DlpExtension = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
