"use strict";

const api = globalThis.browser;
const t = (key, subs) => api.i18n.getMessage(key, subs) || key;
const main = document.getElementById("main");

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "onclick") node.addEventListener("click", value);
    else if (key === "className") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child);
  return node;
}

function show(...nodes) {
  main.replaceChildren(...nodes);
}

function send(message) {
  return api.runtime.sendMessage(message).then((r) => r || { error: "internal" }, () => ({ error: "internal" }));
}

function message(titleKey, textKey, ...extra) {
  show(el("div", { className: "stack" },
    el("p", {}, el("b", {}, t(titleKey))),
    textKey ? el("p", { className: "muted" }, t(textKey)) : "",
    ...extra));
}

function openAppButton() {
  return el("button", { className: "primary wide", onclick: async () => {
    await send({ type: "show_app" });
    window.close();
  } }, t("openApp"));
}

function renderUnlock() {
  const input = el("input", { type: "password", autocomplete: "off", placeholder: t("masterPassword") });
  const button = el("button", { className: "primary wide", type: "submit" }, t("unlock"));
  const note = el("div", { id: "note" });
  const form = el("form", { className: "stack" }, input, button);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!input.value) return;
    button.disabled = true;
    const result = await send({ type: "unlock", password: input.value });
    input.value = "";
    button.disabled = false;
    if (result.ok) {
      main.replaceChildren(el("p", { className: "muted" }, t("popupLoading")));
      start();
      return;
    }
    note.replaceChildren(el("p", { className: "error" }, t("unlockFailed")),
                         result.message ? el("p", { className: "muted" }, result.message) : "");
    input.focus();
  });
  show(el("p", {}, el("b", {}, t("lockedTitle"))),
       el("p", { className: "muted" }, t("unlockText")),
       form, note,
       el("p", { className: "muted small" }, el("a", { href: "#", onclick: async (e) => {
         e.preventDefault();
         await send({ type: "show_app" });
         window.close();
       } }, t("openApp"))));
  input.focus();
}

function renderReady(status) {
  document.getElementById("site").textContent = status.site || "";
  const nodes = [];
  if (status.site === null) {
    nodes.push(el("p", { className: "muted" }, t("notAWebPage")));
  } else if (!status.logins.length) {
    nodes.push(el("p", { className: "muted" }, t("noLogins")));
  } else {
    const list = el("ul", { className: "logins" });
    for (const login of status.logins) {
      list.append(el("li", {}, el("button", { onclick: () => fill(login.id) },
        el("span", { className: "title" }, login.title),
        el("span", { className: "user" }, login.username || t("noUsername")))));
    }
    nodes.push(el("p", { className: "muted" }, t("pickLogin")), list);
  }
  const note = el("div", { id: "note" });
  if (status.site !== null) {
    nodes.push(el("button", { className: "wide", onclick: generate }, t("generate")));
  }
  nodes.push(note);
  show(...nodes);
}

async function fill(id) {
  const result = await send({ type: "fill", id });
  if (result && result.filled) {
    window.close();
    return;
  }
  document.getElementById("note").replaceChildren(
    el("p", { className: "error" }, t(result && result.error ? "fillFailed" : "noFieldFound")));
}

async function generate() {
  const result = await send({ type: "generate" });
  const note = document.getElementById("note");
  if (result.error) {
    note.replaceChildren(el("p", { className: "error" }, t("fillFailed")));
    return;
  }
  note.replaceChildren(
    el("p", { className: "muted" }, t(result.filled ? "generatedFilled" : "generatedCopy")),
    el("div", { className: "generated" }, result.password));
}

async function start() {
  const status = await send({ type: "status" });
  switch (status.state) {
    case "ready":
      return renderReady(status);
    case "unpaired":
      return message("unpairedTitle", "unpairedText",
        el("button", { className: "primary wide", onclick: async () => {
          await api.tabs.create({ url: api.runtime.getURL("pair.html") });
          window.close();
        } }, t("connect")));
    case "locked_can_unlock":
      return renderUnlock();
    case "locked":
    case "locked_unpaired":
      return message("lockedTitle", "lockedText", openAppButton());
    case "app_not_running":
      return message("notRunningTitle", "notRunningText");
    case "host_missing":
      return message("hostMissingTitle", "hostMissingText");
    default:
      return message("errorTitle", null, el("p", { className: "muted" }, String(status.state || status.error)));
  }
}

for (const node of document.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
start();
