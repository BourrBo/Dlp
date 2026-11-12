const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const DlpExtension = require("../extension-core.js");

async function dropDirectory(failClosed) {
  const listeners = new Map();
  let banner;
  const document = {
    addEventListener: (type, handler) => listeners.set(type, handler),
    createElement: () => ({ style: {}, isConnected: false, remove() { this.isConnected = false; } }),
    documentElement: { appendChild: (element) => { element.isConnected = true; banner = element; } },
  };
  const context = vm.createContext({
    Array,
    Blob,
    DataTransfer: class {},
    DlpExtension,
    Event,
    HTMLFormElement: class {},
    HTMLInputElement: class {},
    WeakSet,
    clearTimeout,
    chrome: { runtime: { lastError: null, sendMessage: (_message, callback) => callback({ failClosed }) } },
    document,
    setTimeout: () => 1,
    window: { location: { hostname: "chatgpt.com" }, confirm: () => false },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "content.js"), "utf8"), context);

  const event = {
    dataTransfer: {
      items: [{ kind: "file", webkitGetAsEntry: () => ({ isDirectory: true }) }],
      files: [],
    },
    target: {},
    defaultPrevented: false,
    stopped: false,
    preventDefault() { this.defaultPrevented = true; },
    stopImmediatePropagation() { this.stopped = true; },
  };
  await listeners.get("drop")(event);
  return { event, banner };
}

test("folder drop is blocked when fail-closed is configured", async () => {
  const { event, banner } = await dropDirectory(true);
  assert.equal(event.defaultPrevented, true);
  assert.equal(event.stopped, true);
  assert.match(banner.textContent, /Folder drop blocked/);
});

test("folder drop follows fail-open configuration with a warning", async () => {
  const { event, banner } = await dropDirectory(false);
  assert.equal(event.defaultPrevented, false);
  assert.equal(event.stopped, false);
  assert.match(banner.textContent, /allowed by the fail-open setting/);
});
