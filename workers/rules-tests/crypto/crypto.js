// Test fixture for workers/rules/pathos-crypto.yml (JavaScript). Not executed.
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const https = require("https");

function hashing(data) {
  // ruleid: pathos.crypto.javascript.weak-hash
  const a = crypto.createHash("md5").update(data).digest("hex");
  // ruleid: pathos.crypto.javascript.weak-hash
  const b = crypto.createHmac("sha1", process.env.KEY).update(data).digest();
  // ok: pathos.crypto.javascript.weak-hash
  const c = crypto.createHash("sha256").update(data).digest("hex");
  return [a, b, c];
}

function ciphers(key, data) {
  // ruleid: pathos.crypto.javascript.weak-cipher
  const d = crypto.createCipheriv("des-ede3-cbc", key, crypto.randomBytes(8));
  // ruleid: pathos.crypto.javascript.weak-cipher
  const e = crypto.createCipher("aes-256-cbc", key);
  // ok: pathos.crypto.javascript.weak-cipher
  const f = crypto.createCipheriv("aes-256-gcm", key, crypto.randomBytes(12));
  // ruleid: pathos.crypto.javascript.ecb-mode
  const g = crypto.createCipheriv("aes-128-ecb", key, null);
  // ok: pathos.crypto.javascript.ecb-mode
  const g2 = crypto.createCipheriv("aes-128-gcm", key, crypto.randomBytes(12));
  // ruleid: pathos.crypto.javascript.static-iv
  const h = crypto.createCipheriv("aes-256-cbc", key, "0000000000000000");
  // ruleid: pathos.crypto.javascript.static-iv
  const i = crypto.createCipheriv("aes-256-gcm", key, Buffer.alloc(12));
  // ok: pathos.crypto.javascript.static-iv
  const j = crypto.createCipheriv("aes-256-gcm", key, crypto.randomBytes(12));
  return [d, e, f, g, g2, h, i, j];
}

function keys() {
  // ruleid: pathos.crypto.javascript.small-rsa-key
  const weak = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
  // ok: pathos.crypto.javascript.small-rsa-key
  const strong = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });
  return [weak, strong];
}

function tokens(user) {
  // ruleid: pathos.crypto.javascript.insecure-random-secret
  const resetToken = Math.random().toString(36).slice(2);
  // ruleid: pathos.crypto.javascript.insecure-random-secret
  user.sessionId = Math.floor(Math.random() * 1e16);
  // ok: pathos.crypto.javascript.insecure-random-secret
  const csrfToken = crypto.randomBytes(32).toString("hex");
  // ok: pathos.crypto.javascript.insecure-random-secret
  const jitter = Math.random() * 100;
  return [resetToken, csrfToken, jitter];
}

function tls() {
  // ruleid: pathos.crypto.javascript.tls-verification-disabled
  const agent = new https.Agent({ checkServerIdentity: () => undefined });
  // ok: pathos.crypto.javascript.tls-verification-disabled
  const agent2 = new https.Agent({ ca: process.env.PRIVATE_CA });
  return [agent, agent2];
}

function hardcoded(payload, data) {
  // ruleid: pathos.crypto.javascript.hardcoded-key
  const t = jwt.sign(payload, "fixture-signing-key", { algorithm: "HS256" });
  // ruleid: pathos.crypto.javascript.hardcoded-key
  const c = crypto.createCipheriv("aes-256-gcm", Buffer.from("0123456789abcdef0123456789abcdef"), crypto.randomBytes(12));
  // ok: pathos.crypto.javascript.hardcoded-key
  const t2 = jwt.sign(payload, process.env.JWT_KEY, { algorithm: "HS256" });
  return [t, c, t2, data];
}

module.exports = { hashing, ciphers, keys, tokens, tls, hardcoded };
