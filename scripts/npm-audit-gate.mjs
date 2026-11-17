#!/usr/bin/env node
// npm audit gate: fails on high or critical advisories unless an advisory is
// listed in frontend/audit-exceptions.json with a reason and an expiry date
// (at most 30 days ahead). Expired exceptions fail the build again.
//
//   cd frontend && node ../scripts/npm-audit-gate.mjs
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const MAX_DAYS = 30;
const rank = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

let raw;
try {
  raw = execFileSync("npm", ["audit", "--json"], { encoding: "utf8", maxBuffer: 64 << 20 });
} catch (e) {
  raw = e.stdout; // npm audit exits non-zero when it finds anything
}
const report = JSON.parse(raw);
const exceptions = JSON.parse(readFileSync("audit-exceptions.json", "utf8"));
const now = new Date();
let failed = false;

const excepted = new Map();
for (const ex of exceptions) {
  const days = (new Date(ex.expires + "T23:59:59Z") - now) / 86400000;
  if (!ex.id || !ex.reason || Number.isNaN(days)) {
    console.error(`invalid exception ${JSON.stringify(ex)}: id, reason and expires are required`);
    failed = true;
  } else if (days < 0) {
    console.error(`exception for ${ex.id} expired on ${ex.expires}: fix or re-review it`);
    failed = true;
  } else if (days > MAX_DAYS + 1) {
    console.error(`exception for ${ex.id} expires more than ${MAX_DAYS} days ahead (${ex.expires})`);
    failed = true;
  } else {
    excepted.set(ex.id, ex);
  }
}

const seen = new Set();
for (const [name, v] of Object.entries(report.vulnerabilities ?? {})) {
  for (const via of v.via ?? []) {
    if (typeof via !== "object" || (rank[via.severity] ?? 0) < rank.high) continue;
    const id = (via.url ?? "").split("/").pop() || String(via.source);
    if (seen.has(id + "|" + name)) continue;
    seen.add(id + "|" + name);
    const ex = excepted.get(id);
    if (ex) {
      ex.used = true;
      console.log(`excepted until ${ex.expires}: ${id} (${via.severity}) in ${name}: ${via.title}`);
    } else {
      console.error(`${via.severity}: ${id} in ${name}: ${via.title} ${via.url ?? ""}`);
      failed = true;
    }
  }
}
for (const [id, ex] of excepted) {
  if (!ex.used) console.log(`note: the exception for ${id} is no longer needed; remove it`);
}
process.exit(failed ? 1 : 0);
