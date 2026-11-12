const test = require("node:test");
const assert = require("node:assert/strict");
const DlpExtension = require("../extension-core.js");

test("normalizes destination hostnames, URL inputs, case and www", () => {
  assert.equal(DlpExtension.normalizeHost("HTTPS://WWW.ChatGPT.com/path?q=1"), "chatgpt.com");
  assert.equal(DlpExtension.normalizeHost(" claude.ai. "), "claude.ai");
  assert.equal(DlpExtension.normalizeHost("not a host /"), "");
});

test("matches configured host and its subdomains only", () => {
  const sites = ["chatgpt.com", "claude.ai"];
  assert.equal(DlpExtension.isProtectedDestination("chatgpt.com", sites), true);
  assert.equal(DlpExtension.isProtectedDestination("team.chatgpt.com", sites), true);
  assert.equal(DlpExtension.isProtectedDestination("chatgpt.com.attacker.test", sites), false);
  assert.equal(DlpExtension.isProtectedDestination("notclaude.ai", sites), false);
});

test("normalizes, deduplicates and drops malformed configured entries", () => {
  assert.deepEqual(DlpExtension.normalizeSites(["www.chatgpt.com", "https://chatgpt.com/a", "%%%"]), ["chatgpt.com"]);
  assert.deepEqual(DlpExtension.normalizeSites(null), DlpExtension.DEFAULT_AI_SITES);
});

test("detects dropped folders and treats unreadable file entries conservatively", () => {
  assert.equal(DlpExtension.hasDirectoryItems([
    { kind: "string" },
    { kind: "file", webkitGetAsEntry: () => ({ isDirectory: true }) },
  ]), true);
  assert.equal(DlpExtension.hasDirectoryItems([
    { kind: "file", webkitGetAsEntry: () => ({ isDirectory: false }) },
  ]), false);
  assert.equal(DlpExtension.hasDirectoryItems([
    { kind: "file", webkitGetAsEntry: () => { throw new Error("unavailable"); } },
  ]), true);
});
