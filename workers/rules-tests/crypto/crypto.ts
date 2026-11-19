// Test fixture for workers/rules/pathos-crypto.yml (TypeScript). Not executed.
import { createHash, createCipheriv, randomBytes } from "crypto";

export function digest(data: string): string {
  // ruleid: pathos.crypto.javascript.weak-hash
  return createHash("md5").update(data).digest("hex");
}

export function encrypt(key: Buffer, data: string): Buffer {
  // ruleid: pathos.crypto.javascript.static-iv
  const c = createCipheriv("aes-256-cbc", key, Buffer.from("fixed-iv-16bytes"));
  // ok: pathos.crypto.javascript.static-iv
  const d = createCipheriv("aes-256-gcm", key, randomBytes(12));
  return Buffer.concat([c.update(data), d.final()]);
}
