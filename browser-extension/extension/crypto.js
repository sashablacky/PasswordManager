/*
 * Cryptography of the SecureVault bridge, with WebCrypto.
 *
 * Mirrors src/integration/protocol.py in the program; both sides must stay in
 * sync (tests/test_browser_bridge_js.py runs this file against the program).
 *
 * Pairing: a fresh P-256 key pair per attempt; ECDH with the program's key
 * gives a shared secret, from which come the six-digit code shown on both
 * sides and the key that unwraps the pairing key sent by the program.
 * Sessions: HKDF-SHA256 of the pairing key with both nonces gives one
 * AES-256-GCM key per direction; the sequence number is part of the
 * authenticated data.
 */

"use strict";

const SVCrypto = (() => {
  const subtle = globalThis.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function b64e(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  function b64d(text) {
    const s = atob(text);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  function randomBytes(n) {
    return globalThis.crypto.getRandomValues(new Uint8Array(n));
  }

  async function hkdf(ikm, info, salt = new Uint8Array(0)) {
    const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, key, 256);
    return new Uint8Array(bits);
  }

  async function aesKey(raw, usage) {
    return subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
  }

  // ------------------------------------------------------------ pairing

  async function newKeyPair() {
    const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
    return { privateKey: pair.privateKey, pub };
  }

  async function sharedSecret(privateKey, peerPub) {
    const peer = await subtle.importKey("raw", peerPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const bits = await subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256);
    return new Uint8Array(bits);
  }

  async function pairingCode(secret) {
    const bytes = await hkdf(secret, "securevault-pair-code");
    const n = new DataView(bytes.buffer).getUint32(0, false) % 1000000;
    return String(n).padStart(6, "0");
  }

  async function unwrapPairingKey(secret, clientId, ivB64, ctB64) {
    const key = await aesKey(await hkdf(secret, "securevault-pair-wrap"), "decrypt");
    const plain = await subtle.decrypt(
      { name: "AES-GCM", iv: b64d(ivB64), additionalData: enc.encode(`securevault-pair|${clientId}`) },
      key, b64d(ctB64));
    return new Uint8Array(plain);
  }

  // ------------------------------------------------------------ sessions

  // Returns plain data (base64 keys), so it can be kept in storage.session
  async function newSession(sessionId, pairingKey, clientNonce, serverNonce) {
    const salt = new Uint8Array(clientNonce.length + serverNonce.length);
    salt.set(clientNonce, 0);
    salt.set(serverNonce, clientNonce.length);
    return {
      id: sessionId,
      c2s: b64e(await hkdf(pairingKey, "securevault-session-c2s", salt)),
      s2c: b64e(await hkdf(pairingKey, "securevault-session-s2c", salt)),
      seq: 0,
    };
  }

  async function seal(session, payload, seq) {
    const iv = randomBytes(12);
    const key = await aesKey(b64d(session.c2s), "encrypt");
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(`c2s|${session.id}|${seq}`) },
      key, enc.encode(JSON.stringify(payload)));
    return { type: "enc", session: session.id, seq, iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
  }

  async function unseal(session, message, expectedSeq) {
    if (message.session !== session.id || message.seq !== expectedSeq) {
      throw new Error("reply does not belong to this request");
    }
    const key = await aesKey(b64d(session.s2c), "decrypt");
    const plain = await subtle.decrypt(
      { name: "AES-GCM", iv: b64d(message.iv), additionalData: enc.encode(`s2c|${session.id}|${message.seq}`) },
      key, b64d(message.ct));
    return JSON.parse(dec.decode(plain));
  }

  return { b64e, b64d, randomBytes, newKeyPair, sharedSecret, pairingCode, unwrapPairingKey,
           newSession, seal, unseal };
})();

if (typeof module !== "undefined") module.exports = SVCrypto;
