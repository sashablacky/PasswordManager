// Runs the extension's background.js in Node with a stand-in for the browser
// API whose native messaging starts the real native host, like Firefox does.
// Used by tests/test_browser_bridge_js.py; prints one JSON line of results.

"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const EXT = path.join(__dirname, "..", "..", "browser-extension", "extension");
const [python, hostScript, masterPassword] = process.argv.slice(2);

function memoryArea() {
  const data = {};
  return {
    data,
    async get(key) { return key in data ? { [key]: data[key] } : {}; },
    async set(values) { Object.assign(data, JSON.parse(JSON.stringify(values))); },
    async remove(keys) { for (const k of [].concat(keys)) delete data[k]; },
  };
}

function nativeMessage(message) {
  return new Promise((resolve, reject) => {
    const child = spawn(python, ["-u", hostScript], { stdio: ["pipe", "pipe", "inherit"] });
    const chunks = [];
    child.stdout.on("data", (c) => chunks.push(c));
    child.on("error", reject);
    child.on("close", () => {
      const out = Buffer.concat(chunks);
      if (out.length < 4) return reject(new Error("no reply from host"));
      resolve(JSON.parse(out.subarray(4, 4 + out.readUInt32LE(0)).toString("utf8")));
    });
    const body = Buffer.from(JSON.stringify(message), "utf8");
    const header = Buffer.alloc(4);
    header.writeUInt32LE(body.length);
    child.stdin.end(Buffer.concat([header, body]));
  });
}

const listeners = [];
const toTab = [];
let tabUrl = "https://example.com/login";

const browser = {
  storage: { local: memoryArea(), session: memoryArea() },
  runtime: {
    sendNativeMessage: (host, message) => nativeMessage(message),
    onMessage: { addListener: (f) => listeners.push(f) },
    getURL: (p) => "moz-extension://test/" + p,
  },
  tabs: {
    query: async () => [{ id: 7, url: tabUrl }],
    sendMessage: async (tabId, message, options) => { toTab.push({ tabId, message, options }); return { filled: true }; },
    onRemoved: { addListener() {} },
    create: async () => ({}),
  },
  commands: { onCommand: { addListener() {} } },
  i18n: { getMessage: (k) => k },
};

const context = vm.createContext({ browser, console, crypto: globalThis.crypto, navigator: { userAgent: "Firefox/140.0" },
                                   TextEncoder, TextDecoder, btoa, atob, setTimeout, URL });
for (const file of ["crypto.js", "background.js"]) {
  vm.runInContext(fs.readFileSync(path.join(EXT, file), "utf8"), context, { filename: file });
}

// Senders as Firefox describes them: the popup has no tab, the pairing page is
// an extension page in a tab, content scripts report the web page
const fromPopup = (message) => listeners[0](message, { url: browser.runtime.getURL("popup.html") });
const fromPairPage = (message) => listeners[0](message, { tab: { id: 9 }, frameId: 0,
                                                          url: browser.runtime.getURL("pair.html") });
const fromPage = (message, url = tabUrl) => listeners[0](message, { tab: { id: 7 }, frameId: 0, url });

async function main() {
  const r = {};
  r.statusBefore = (await fromPopup({ type: "status" })).state;
  r.pairStart = await fromPairPage({ type: "pair_start" });
  r.pairPoll = (await fromPairPage({ type: "pair_poll" })).state;
  r.status = await fromPopup({ type: "status" });

  r.fill = await fromPopup({ type: "fill", id: r.status.logins[0].id });
  r.filledMessage = toTab.pop();

  // Signing in with a new password on another site, then saving it from the bar
  tabUrl = "https://shop.example.org/account";
  await fromPage({ type: "login_submitted", username: "carol", password: "Shop-Pass-1" });
  await new Promise((res) => setTimeout(res, 50));
  for (let i = 0; i < 100 && !toTab.length; i++) await new Promise((res) => setTimeout(res, 50));
  r.saveBar = toTab.pop();
  r.pending = await fromPage({ type: "get_pending" });
  r.save = await fromPage({ type: "save_bar_action", action: "save" });
  r.pendingAfter = await fromPage({ type: "get_pending" });
  r.statusShop = await fromPopup({ type: "status" });

  // The page itself may not use the popup's requests
  r.pageFill = (await fromPage({ type: "fill", id: 1 })) ?? null;
  r.generate = await fromPopup({ type: "generate" });
  r.storedKeys = Object.keys(browser.storage.local.data).sort();

  // Locked vault: the popup asks for the master password
  await nativeMessage({ type: "test_lock" });
  r.lockedStatus = (await fromPopup({ type: "status" })).state;
  r.badUnlock = await fromPopup({ type: "unlock", password: "wrong password" });
  r.goodUnlock = await fromPopup({ type: "unlock", password: masterPassword });
  r.afterUnlock = (await fromPopup({ type: "status" })).state;
  process.stdout.write(JSON.stringify(r) + "\n");
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ error: String(e && e.stack || e) }) + "\n");
  process.exitCode = 1;
});
