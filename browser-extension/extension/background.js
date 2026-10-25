/*
 * Background script: the only part of the extension that talks to the program.
 *
 * Messages go through native messaging (Firefox: the securevault_host.py
 * relay, Safari: the Swift handler of the app around the extension) to the
 * running SecureVault program. Everything except the "hello" and pairing
 * messages is encrypted with the session keys (crypto.js).
 *
 * Pages never get anything from here on their own: content scripts receive a
 * password only when the user picked a login in the popup or pressed the
 * shortcut, and only in the top frame of the tab whose address matched.
 */

"use strict";

const HOST = "com.securevault.bridge";
const PENDING_SAVE_SECONDS = 90;

const api = globalThis.browser;

// ------------------------------------------------------------ storage helpers

async function localGet(key) {
  return (await api.storage.local.get(key))[key];
}

async function sessionGet(key) {
  return (await api.storage.session.get(key))[key];
}

async function clientId() {
  let id = await localGet("clientId");
  if (!id) {
    id = crypto.randomUUID();
    await api.storage.local.set({ clientId: id });
  }
  return id;
}

function browserName() {
  const ua = navigator.userAgent;
  if (ua.includes("Firefox/")) return "Firefox";
  if (ua.includes("Safari/") && !ua.includes("Chrome/")) return "Safari";
  return "Browser";
}

// ------------------------------------------------------------ native messaging

async function nativeSend(message) {
  try {
    const reply = await api.runtime.sendNativeMessage(HOST, message);
    return reply && typeof reply === "object" ? reply : { type: "error", code: "host_missing" };
  } catch (e) {
    console.warn("SecureVault: native messaging failed", e);
    return { type: "error", code: "host_missing" };
  }
}

// Requests go out one at a time, so sequence numbers arrive in order
let queue = Promise.resolve();
function serialized(fn) {
  const run = queue.then(fn, fn);
  queue = run.catch(() => {});
  return run;
}

// ------------------------------------------------------------ session

async function openSession() {
  const pairingKey = await localGet("pairingKey");
  const nonce = SVCrypto.randomBytes(16);
  const reply = await nativeSend({ type: "hello", client_id: pairingKey ? await clientId() : null,
                                   nonce: SVCrypto.b64e(nonce) });
  if (reply.type === "error") return { state: reply.code };
  if (reply.state !== "ready") return { state: reply.state };
  const session = await SVCrypto.newSession(reply.session, SVCrypto.b64d(pairingKey), nonce,
                                            SVCrypto.b64d(reply.nonce));
  await api.storage.session.set({ session });
  return { state: "ready", session };
}

async function callOnce(action, params) {
  let session = await sessionGet("session");
  if (!session) {
    const opened = await openSession();
    if (opened.state !== "ready") return { error: opened.state };
    session = opened.session;
  }
  session.seq += 1;
  await api.storage.session.set({ session });
  const reply = await nativeSend(await SVCrypto.seal(session, { ...params, action }, session.seq));
  if (reply.type === "error") {
    if (reply.code === "session_expired" || reply.code === "bad_message") {
      await api.storage.session.remove("session");
      return { error: "session_expired" };
    }
    return { error: reply.code };
  }
  try {
    return await SVCrypto.unseal(session, reply, session.seq);
  } catch (e) {
    await api.storage.session.remove("session");
    return { error: "bad_reply" };
  }
}

// One retry with a fresh session: after the vault was locked and unlocked again
function call(action, params = {}) {
  return serialized(async () => {
    const result = await callOnce(action, params);
    return result.error === "session_expired" ? callOnce(action, params) : result;
  });
}

// ------------------------------------------------------------ pairing

async function pairStart() {
  return serialized(async () => {
    const id = await clientId();
    const { privateKey, pub } = await SVCrypto.newKeyPair();
    const reply = await nativeSend({ type: "pair_request", client_id: id, browser: browserName(),
                                     pub: SVCrypto.b64e(pub) });
    if (reply.type === "error") return { error: reply.code };
    const secret = await SVCrypto.sharedSecret(privateKey, SVCrypto.b64d(reply.pub));
    const code = await SVCrypto.pairingCode(secret);
    await api.storage.session.set({ pairing: { id: reply.pairing, secret: SVCrypto.b64e(secret), code } });
    return { code };
  });
}

async function pairPoll() {
  return serialized(async () => {
    const pairing = await sessionGet("pairing");
    if (!pairing) return { state: "expired" };
    const reply = await nativeSend({ type: "pair_status", pairing: pairing.id });
    if (reply.type === "error") return { state: "error", error: reply.code };
    if (reply.state === "pending") return { state: "pending", code: pairing.code };
    await api.storage.session.remove("pairing");
    if (reply.state !== "approved") return { state: reply.state };
    const keys = await SVCrypto.unwrapPairingKey(SVCrypto.b64d(pairing.secret), await clientId(), reply.iv, reply.ct);
    // The pairing key, followed by the key for sending the master password when the vault is locked
    await api.storage.local.set({ pairingKey: SVCrypto.b64e(keys.slice(0, 32)),
                                  unlockKey: SVCrypto.b64e(keys.slice(32)) });
    await api.storage.session.remove("session");
    return { state: "approved" };
  });
}

// ------------------------------------------------------------ unlocking

async function unlockWithPassword(password) {
  if (typeof password !== "string" || !password) return { ok: false, error: "missing_password" };
  return serialized(async () => {
    const unlockKey = await localGet("unlockKey");
    if (!unlockKey) return { ok: false, error: "unpaired" };
    const id = await clientId();
    const hello = await nativeSend({ type: "hello", client_id: id, nonce: SVCrypto.b64e(SVCrypto.randomBytes(16)) });
    if (hello.type === "error") return { ok: false, error: hello.code };
    if (hello.state !== "locked") return { ok: hello.state === "ready" };
    if (!hello.unlock) return { ok: false, error: "unpaired" };
    const { privateKey, pub } = await SVCrypto.newKeyPair();
    const secret = await SVCrypto.sharedSecret(privateKey, SVCrypto.b64d(hello.unlock.pub));
    const sealed = await SVCrypto.sealUnlock(SVCrypto.b64d(unlockKey), secret, SVCrypto.b64d(hello.unlock.nonce),
                                             id, hello.unlock.id, password);
    const reply = await nativeSend({ type: "unlock", client_id: id, id: hello.unlock.id,
                                     pub: SVCrypto.b64e(pub), ...sealed });
    if (reply.type === "error") return { ok: false, error: reply.code };
    if (reply.ok) await api.storage.session.remove("session");
    return { ok: !!reply.ok, message: reply.message || "" };
  });
}

// ------------------------------------------------------------ tabs

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function isWebPage(url) {
  return /^https?:\/\//i.test(url || "");
}

async function fillLogin(tab, id) {
  if (!tab || !isWebPage(tab.url)) return { error: "not_a_web_page" };
  const login = await call("get_login", { id, url: tab.url });
  if (login.error) return login;
  try {
    return await api.tabs.sendMessage(tab.id, {
      type: "fill", username: login.username, password: login.password, url: tab.url,
    }, { frameId: 0 });
  } catch (e) {
    return { error: "page_not_ready" };
  }
}

async function fillFirstLogin() {
  const tab = await activeTab();
  if (!tab || !isWebPage(tab.url)) return;
  const result = await call("get_logins", { url: tab.url });
  if (result.logins && result.logins.length) {
    await fillLogin(tab, result.logins[0].id);
  }
}

async function generateIntoPage() {
  const tab = await activeTab();
  const result = await call("generate_password", {});
  if (result.error) return result;
  if (tab && isWebPage(tab.url)) {
    try {
      const filled = await api.tabs.sendMessage(tab.id, { type: "fill_generated", password: result.password,
                                                         url: tab.url }, { frameId: 0 });
      result.filled = !!(filled && filled.filled);
    } catch (e) {
      result.filled = false;
    }
  }
  return result;
}

// ------------------------------------------------------------ saving logins

// tabId -> {url, site, username, password, state, id, expires}; in memory only
const pendingSaves = new Map();

function pendingFor(tabId) {
  const pending = pendingSaves.get(tabId);
  if (pending && pending.expires < Date.now()) {
    pendingSaves.delete(tabId);
    return null;
  }
  return pending || null;
}

function publicPrompt(pending) {
  return { state: pending.state, site: pending.site, username: pending.username };
}

async function onLoginSubmitted(sender, username, password) {
  if (!sender.tab || !isWebPage(sender.url) || typeof password !== "string" || !password) return;
  const check = await call("check_login", { url: sender.url, username: username || "", password });
  if (check.error || check.state === "same") return;
  const pending = {
    url: sender.url,
    site: new URL(sender.url).hostname.replace(/^www\./, ""),
    username: username || "",
    password,
    state: check.state,
    id: check.id,
    expires: Date.now() + PENDING_SAVE_SECONDS * 1000,
  };
  pendingSaves.set(sender.tab.id, pending);
  try {
    // Pages that stay put after signing in show the question right away;
    // others ask for it when the next page loads (get_pending)
    await api.tabs.sendMessage(sender.tab.id, { type: "show_save_bar", prompt: publicPrompt(pending) },
                               { frameId: 0 });
  } catch (e) {
    // the page is navigating
  }
}

async function onSaveBarAction(sender, action) {
  const tabId = sender.tab && sender.tab.id;
  const pending = pendingFor(tabId);
  pendingSaves.delete(tabId);
  if (!pending || action === "dismiss") return { ok: true };
  if (action === "save" && pending.state === "new") {
    return call("save_login", { url: pending.url, username: pending.username, password: pending.password });
  }
  if (action === "update" && pending.state === "changed") {
    return call("update_login", { id: pending.id, url: pending.url, password: pending.password });
  }
  return { error: "bad_action" };
}

api.tabs.onRemoved.addListener((tabId) => pendingSaves.delete(tabId));

// ------------------------------------------------------------ popup status

async function popupStatus() {
  const tab = await activeTab();
  const pairingKey = await localGet("pairingKey");
  if (!pairingKey) {
    // Still check that the program can be reached, to show the right hint
    const hello = await serialized(() => nativeSend({ type: "hello", client_id: null, nonce: SVCrypto.b64e(SVCrypto.randomBytes(16)) }));
    if (hello.type === "error") return { state: hello.code };
    return { state: hello.state === "locked" ? "locked_unpaired" : "unpaired" };
  }
  if (!tab || !isWebPage(tab.url)) {
    const ping = await call("ping");
    if (ping.error === "locked" && await localGet("unlockKey")) return { state: "locked_can_unlock" };
    return ping.error ? { state: ping.error } : { state: "ready", site: null, logins: [] };
  }
  const result = await call("get_logins", { url: tab.url });
  if (result.error) {
    if (result.error === "unpaired") await api.storage.local.remove(["pairingKey", "unlockKey"]);
    if (result.error === "locked" && await localGet("unlockKey")) return { state: "locked_can_unlock" };
    return { state: result.error };
  }
  return { state: "ready", site: result.site, logins: result.logins };
}

// ------------------------------------------------------------ messages

api.runtime.onMessage.addListener((message, sender) => {
  if (!message || typeof message.type !== "string") return undefined;
  // Content scripts report the web page as their URL. The pairing page is our
  // own page but lives in a tab, so sender.tab alone does not tell them apart.
  const fromPage = !(sender.url || "").startsWith(api.runtime.getURL(""));

  // From content scripts
  if (fromPage) {
    switch (message.type) {
      case "login_submitted":
        onLoginSubmitted(sender, message.username, message.password);
        return Promise.resolve({ ok: true });
      case "get_pending": {
        const pending = sender.frameId === 0 ? pendingFor(sender.tab.id) : null;
        return Promise.resolve(pending ? publicPrompt(pending) : null);
      }
      case "save_bar_action":
        return onSaveBarAction(sender, message.action);
      default:
        // A page (even a compromised content script) must not use the popup's requests
        return undefined;
    }
  }

  // From the popup and the pairing page
  switch (message.type) {
    case "status":
      return popupStatus();
    case "pair_start":
      return pairStart();
    case "pair_poll":
      return pairPoll();
    case "fill":
      return activeTab().then((tab) => fillLogin(tab, message.id));
    case "generate":
      return generateIntoPage();
    case "unlock":
      return unlockWithPassword(message.password);
    case "show_app":
      return serialized(() => nativeSend({ type: "show_app" }));
    case "unpair":
      return api.storage.local.remove(["pairingKey", "unlockKey"]).then(() => api.storage.session.remove("session"))
        .then(() => ({ ok: true }));
    default:
      return undefined;
  }
});

api.commands.onCommand.addListener((command) => {
  if (command === "fill-login") fillFirstLogin();
});

// ------------------------------------------------------------ the browser's own password manager

// Firefox's password manager would offer to save and fill the same logins on
// top of ours. Turned off while the extension is installed and enabled; the
// browser restores the user's setting when it is disabled or removed.
// Safari has no privacy API.
async function turnOffBrowserPasswordSaving() {
  const setting = api.privacy && api.privacy.services && api.privacy.services.passwordSavingEnabled;
  if (!setting) return;
  try {
    const current = await setting.get({});
    if (current.value && current.levelOfControl === "controllable_by_this_extension") {
      await setting.set({ value: false });
    }
  } catch (e) {
    console.warn("SecureVault: could not turn off the browser's password saving", e);
  }
}

if (api.runtime.onInstalled) api.runtime.onInstalled.addListener(turnOffBrowserPasswordSaving);
if (api.runtime.onStartup) api.runtime.onStartup.addListener(turnOffBrowserPasswordSaving);
