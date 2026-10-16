// Pairs with the program and makes encrypted requests using the extension's
// crypto.js. Talks JSON lines on stdin/stdout to tests/test_browser_bridge_js.py,
// which hands every message to BridgeService.handle().

"use strict";

const path = require("path");
const readline = require("readline");
const SVCrypto = require(path.join(__dirname, "..", "..", "browser-extension", "extension", "crypto.js"));

const lines = readline.createInterface({ input: process.stdin });
const waiting = [];
lines.on("line", (line) => waiting.shift()(JSON.parse(line)));

function send(message) {
  return new Promise((resolve) => {
    waiting.push(resolve);
    process.stdout.write(JSON.stringify(message) + "\n");
  });
}

async function main() {
  const clientId = globalThis.crypto.randomUUID();
  const { privateKey, pub } = await SVCrypto.newKeyPair();
  const pending = await send({ type: "pair_request", client_id: clientId, browser: "Node", pub: SVCrypto.b64e(pub) });
  const secret = await SVCrypto.sharedSecret(privateKey, SVCrypto.b64d(pending.pub));
  const code = await SVCrypto.pairingCode(secret);
  const status = await send({ type: "pair_status", pairing: pending.pairing });
  const pairingKey = await SVCrypto.unwrapPairingKey(secret, clientId, status.iv, status.ct);

  const nonce = SVCrypto.randomBytes(16);
  const hello = await send({ type: "hello", client_id: clientId, nonce: SVCrypto.b64e(nonce) });
  const session = await SVCrypto.newSession(hello.session, pairingKey, nonce, SVCrypto.b64d(hello.nonce));

  const results = [];
  for (const [action, params] of [["ping", {}], ["get_logins", { url: "https://example.com/login" }]]) {
    session.seq += 1;
    const reply = await send(await SVCrypto.seal(session, { ...params, action }, session.seq));
    results.push(await SVCrypto.unseal(session, reply, session.seq));
  }
  process.stdout.write(JSON.stringify({ done: true, code, results }) + "\n");
  process.exit(0);
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ done: true, error: String(e && e.stack || e) }) + "\n");
  process.exit(1);
});
