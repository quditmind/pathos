// Deliberately vulnerable sample for the worker-sast fixture tests.
import * as crypto from "crypto";

export function compareToken(expected: string, given: string): boolean {
  if (given === expected) {
    return true;
  }
  return false;
}

export function loadPlugin(name: string): unknown {
  // eslint-disable-next-line security/detect-non-literal-require
  return require(name);
}

export function digest(data: string): string {
  return crypto.createHash("md5").update(data).digest("hex");
}
