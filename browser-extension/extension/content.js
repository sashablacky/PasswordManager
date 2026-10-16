/*
 * Content script: finds login fields, fills them when asked by the
 * background script, and notices when the user signs in so it can offer to
 * save the password.
 *
 * It never asks for passwords by itself. The question "save this password?"
 * is drawn in a closed shadow root, and only real clicks (isTrusted) on it
 * count, so the page can't answer it for the user.
 */

(() => {
  "use strict";

  if (window.__secureVaultContent) return;
  window.__secureVaultContent = true;

  const api = globalThis.browser;
  const t = (key, subs) => api.i18n.getMessage(key, subs) || key;

  // ------------------------------------------------------------ fields

  function isVisible(el) {
    if (!el || el.disabled) return false;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none") return false;
    return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  }

  function passwordFields(scope = document) {
    return [...scope.querySelectorAll("input[type=password]")].filter((el) => isVisible(el) && !el.readOnly);
  }

  const USERNAME_TYPES = new Set(["text", "email", "tel", ""]);

  function isUsernameInput(el) {
    return el.tagName === "INPUT" && USERNAME_TYPES.has((el.getAttribute("type") || "").toLowerCase()) &&
      isVisible(el) && !el.readOnly;
  }

  function usernameFieldFor(passwordField) {
    const scope = (passwordField && passwordField.form) || document;
    const inputs = [...scope.querySelectorAll("input")];
    const index = passwordField ? inputs.indexOf(passwordField) : inputs.length;
    for (let i = index - 1; i >= 0; i--) {
      if (isUsernameInput(inputs[i])) return inputs[i];
    }
    // Sign-in in two steps (address first, password on the next screen)
    const hinted = [...document.querySelectorAll(
      "input[autocomplete~=username], input[autocomplete~=email], input[type=email], " +
      "input[name*=user i], input[name*=login i], input[name*=email i], input[id*=user i], input[id*=email i]")];
    return hinted.find(isUsernameInput) || null;
  }

  function setValue(el, value) {
    el.focus();
    // The native setter, so pages built with React and similar notice the change
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function sameSite(url) {
    try {
      return new URL(url).host === location.host;
    } catch (e) {
      return false;
    }
  }

  function fillLogin(username, password) {
    const fields = passwordFields();
    const passwordField = fields.find((f) => f.autocomplete !== "new-password") || fields[0] || null;
    const usernameField = usernameFieldFor(passwordField);
    if (usernameField && username) setValue(usernameField, username);
    if (passwordField) setValue(passwordField, password);
    return { filled: !!(passwordField || (usernameField && username)) };
  }

  function fillGenerated(password) {
    const fields = passwordFields();
    const fresh = fields.filter((f) => f.autocomplete === "new-password");
    const targets = (fresh.length ? fresh : fields.filter((f) => !f.value)).slice(0, 2);
    targets.forEach((f) => setValue(f, password));
    return { filled: targets.length > 0 };
  }

  // ------------------------------------------------------------ noticing sign-in

  let lastSent = "";

  function capture(scope) {
    const fields = passwordFields(scope).filter((f) => f.value);
    if (!fields.length) return;
    let password = fields[0].value;
    // Registration or password change: new password + confirmation
    if (fields.length >= 2 && fields[fields.length - 1].value === fields[fields.length - 2].value) {
      password = fields[fields.length - 1].value;
    }
    const usernameField = usernameFieldFor(fields[0]);
    const username = usernameField ? usernameField.value.trim() : "";
    const key = username + "\u0000" + password;
    if (key === lastSent) return;
    lastSent = key;
    api.runtime.sendMessage({ type: "login_submitted", username, password }).catch(() => {});
  }

  document.addEventListener("submit", (e) => {
    if (e.isTrusted && e.target instanceof HTMLFormElement) capture(e.target);
  }, true);

  // Many sites sign in from a button with JavaScript, without a real form submit
  document.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    const button = e.target instanceof Element && e.target.closest("button, input[type=submit], [role=button]");
    if (!button) return;
    const form = button.closest("form");
    // Inside a form only the submit button counts (not "show password" and the like)
    if (form && button.type !== "submit") return;
    const scope = form || document;
    if (passwordFields(scope).some((f) => f.value)) capture(scope);
  }, true);

  document.addEventListener("keydown", (e) => {
    if (e.isTrusted && e.key === "Enter" && e.target instanceof HTMLInputElement && e.target.type === "password") {
      capture(e.target.form || document);
    }
  }, true);

  // ------------------------------------------------------------ save bar

  let bar = null;

  function closeBar() {
    if (bar) bar.remove();
    bar = null;
  }

  function showSaveBar(prompt) {
    if (window !== window.top || !prompt) return;
    closeBar();
    const host = document.createElement("div");
    host.style.cssText = "all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647;";
    const root = host.attachShadow({ mode: "closed" });
    const isUpdate = prompt.state === "changed";
    const who = prompt.username ? `${prompt.username} · ${prompt.site}` : prompt.site;
    root.innerHTML = `
      <style>
        .card { font: 14px/1.4 -apple-system, "Segoe UI", system-ui, sans-serif; color: #D6D1C7;
                background: #252B32; border: 1px solid #3E4954; border-radius: 12px; padding: 14px 16px;
                width: 300px; box-shadow: 0 8px 28px rgba(0,0,0,.35); }
        .title { font-weight: 600; margin-bottom: 2px; }
        .who { color: #A9A49B; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 12px; }
        button { font: inherit; border-radius: 8px; padding: 6px 14px; cursor: pointer; border: 1px solid #3E4954;
                 background: transparent; color: #D6D1C7; }
        button.primary { background: #C8B898; color: #1C2127; border-color: #C8B898; font-weight: 600; }
        .brand { font-size: 12px; color: #9DB1A5; margin-bottom: 6px; letter-spacing: .02em; }
      </style>
      <div class="card" role="dialog">
        <div class="brand">SecureVault</div>
        <div class="title"></div>
        <div class="who"></div>
        <div class="row">
          <button class="later"></button>
          <button class="primary"></button>
        </div>
      </div>`;
    root.querySelector(".title").textContent = t(isUpdate ? "saveBarUpdateTitle" : "saveBarSaveTitle");
    root.querySelector(".who").textContent = who;
    const primary = root.querySelector(".primary");
    primary.textContent = t(isUpdate ? "saveBarUpdate" : "saveBarSave");
    const later = root.querySelector(".later");
    later.textContent = t("saveBarLater");

    later.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      api.runtime.sendMessage({ type: "save_bar_action", action: "dismiss" }).catch(() => {});
      closeBar();
    });
    primary.addEventListener("click", async (e) => {
      if (!e.isTrusted) return;
      primary.disabled = true;
      later.disabled = true;
      const result = await api.runtime.sendMessage({ type: "save_bar_action",
                                                     action: isUpdate ? "update" : "save" }).catch(() => null);
      root.querySelector(".title").textContent = t(result && !result.error ? "saveBarDone" : "saveBarFailed");
      root.querySelector(".row").remove();
      setTimeout(closeBar, 2500);
    });

    (document.body || document.documentElement).appendChild(host);
    bar = host;
  }

  // ------------------------------------------------------------ messages from the background

  api.runtime.onMessage.addListener((message) => {
    if (!message || window !== window.top) return undefined;
    // The tab may have moved to another site since the request was made
    if ((message.type === "fill" || message.type === "fill_generated") && !sameSite(message.url)) {
      return Promise.resolve({ filled: false });
    }
    switch (message.type) {
      case "fill":
        return Promise.resolve(fillLogin(message.username, message.password));
      case "fill_generated":
        return Promise.resolve(fillGenerated(message.password));
      case "show_save_bar":
        showSaveBar(message.prompt);
        return Promise.resolve({ ok: true });
      default:
        return undefined;
    }
  });

  if (window === window.top) {
    api.runtime.sendMessage({ type: "get_pending" }).then(showSaveBar).catch(() => {});
  }
})();
