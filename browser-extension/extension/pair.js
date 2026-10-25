"use strict";

// Opened in a tab (not the popup), so it stays visible while the user
// switches to the program to allow the connection.

const api = globalThis.browser;
const t = (key, subs) => api.i18n.getMessage(key, subs) || key;
const main = document.getElementById("main");

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function show(...nodes) {
  main.replaceChildren(...nodes);
}

function failed(textKey) {
  const retry = el("button", "primary", t("tryAgain"));
  retry.addEventListener("click", start);
  show(el("h1", "", t("pairFailedTitle")), el("p", "muted", t(textKey)), retry);
}

const ERRORS = {
  locked: "pairLocked",
  busy: "pairBusy",
  app_not_running: "notRunningText",
  host_missing: "hostMissingText",
};

async function poll() {
  const result = await api.runtime.sendMessage({ type: "pair_poll" }).catch(() => null) || { state: "error" };
  if (result.state === "pending") {
    setTimeout(poll, 1000);
    return;
  }
  if (result.state === "approved") {
    show(el("h1", "", t("pairDoneTitle")), el("p", "muted", t("pairDoneText")));
    return;
  }
  failed(result.state === "rejected" ? "pairRejected" : result.error ? (ERRORS[result.error] || "pairExpired")
                                                                     : "pairExpired");
}

async function start() {
  document.title = t("pairTitle");
  show(el("p", "muted", t("popupLoading")));
  const result = await api.runtime.sendMessage({ type: "pair_start" }).catch(() => null) || { error: "internal" };
  if (result.error) {
    failed(ERRORS[result.error] || "pairExpired");
    return;
  }
  const steps = el("ol");
  steps.append(el("li", "", t("pairStep1")), el("li", "", t("pairStep2")), el("li", "", t("pairStep3")));
  show(el("h1", "", t("pairTitle")), el("div", "code", `${result.code.slice(0, 3)} ${result.code.slice(3)}`),
       steps, el("p", "muted", t("pairWaiting")));
  setTimeout(poll, 1000);
}

start();
