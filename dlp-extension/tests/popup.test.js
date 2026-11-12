const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadPopup(config) {
  const elements = new Map();
  const localWrites = [];
  for (const id of ["enabled", "openOptions", "events"]) {
    elements.set(id, {
      checked: false,
      disabled: false,
      title: "",
      innerHTML: "",
      addEventListener(type, handler) { this[`on${type}`] = handler; },
    });
  }
  const context = vm.createContext({
    chrome: {
      runtime: {
        sendMessage: (_message, callback) => callback(config),
        openOptionsPage: () => undefined,
      },
      storage: {
        local: {
          get: async () => ({ recentEvents: [] }),
          set: async (value) => localWrites.push(value),
        },
      },
    },
    document: { getElementById: (id) => elements.get(id) },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "popup.js"), "utf8"), context);
  return { elements, localWrites };
}

test("popup reflects the effective worker setting and saves local changes where scans read them", async () => {
  const { elements, localWrites } = loadPopup({ enabled: false, managedKeys: [] });
  await new Promise((resolve) => setImmediate(resolve));
  const toggle = elements.get("enabled");
  assert.equal(toggle.checked, false);
  assert.equal(toggle.disabled, false);
  await toggle.onchange({ target: { checked: true } });
  assert.deepEqual(JSON.parse(JSON.stringify(localWrites)), [{ enabled: true }]);
});

test("popup does not offer a toggle when the setting is administrator managed", async () => {
  const { elements, localWrites } = loadPopup({ enabled: true, managedKeys: ["enabled"] });
  await new Promise((resolve) => setImmediate(resolve));
  const toggle = elements.get("enabled");
  assert.equal(toggle.checked, true);
  assert.equal(toggle.disabled, true);
  assert.match(toggle.title, /managed by your administrator/i);
  assert.deepEqual(JSON.parse(JSON.stringify(localWrites)), []);
});
