// PATHOS API load test: a weighted mix of the read paths a security team
// uses all day (dashboard, findings browsing and filtering, search, SBOM,
// repositories), at a constant arrival rate, with latency and error
// thresholds. Run through scripts/load/run.sh, which logs in and seeds data.
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.PATHOS_URL || "https://localhost";
const COOKIE = __ENV.PATHOS_COOKIE; // "name=value" of a logged-in session
const RATE = Number(__ENV.RATE || 20); // requests per second
const DURATION = __ENV.DURATION || "60s";

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    browse: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_req_duration{kind:list}": ["p(95)<800"],
    "http_req_duration{kind:detail}": ["p(95)<300"],
    "http_req_duration{kind:dashboard}": ["p(95)<1500"],
    checks: ["rate>0.99"],
  },
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
};

const params = (name, kind) => ({ headers: { Cookie: COOKIE, Accept: "application/json" }, tags: { name, kind } });

export function setup() {
  const r = http.get(`${BASE}/api/v1/findings?status=all`, params("setup", "setup"));
  if (r.status !== 200) throw new Error(`login/session not accepted: HTTP ${r.status}`);
  const ids = (r.json("items") || []).map((f) => f.id);
  const repos = (http.get(`${BASE}/api/v1/repositories?limit=100`, params("setup", "setup")).json("items") || []).map((x) => x.id);
  if (!ids.length || !repos.length) throw new Error("no seeded data visible; run scripts/load/run.sh --seed");
  return { ids, repos };
}

const pick = (a) => a[Math.floor(Math.random() * a.length)];

const mix = [
  [12, "dashboard", "dashboard", () => "/api/v1/dashboard"],
  [20, "findings list", "list", () => "/api/v1/findings"],
  [10, "findings filtered", "list", () => `/api/v1/findings?severity=critical,high&category=${pick(["sca", "sast", "secrets"])}`],
  [8, "findings by repo", "list", (d) => `/api/v1/findings?repository_id=${pick(d.repos)}`],
  [6, "findings search", "list", () => `/api/v1/findings?q=${pick(["injection", "CVE-2026-1", "credential", "lib-42"])}`],
  [6, "findings sla breached", "list", () => "/api/v1/findings?sla=breached"],
  [10, "findings summary", "list", () => "/api/v1/findings/summary"],
  [10, "finding detail", "detail", (d) => `/api/v1/findings/${pick(d.ids)}`],
  [5, "finding history", "detail", (d) => `/api/v1/findings/${pick(d.ids)}/history`],
  [5, "repositories", "list", () => "/api/v1/repositories?limit=50"],
  [3, "global search", "list", () => `/api/v1/search?q=${pick(["service-1", "payments", "lib"])}`],
  [3, "sbom components", "list", () => "/api/v1/sbom/components?license=violations"],
  [2, "inbox", "detail", () => "/api/v1/me/notifications"],
];
const total = mix.reduce((s, m) => s + m[0], 0);

export default function (data) {
  let x = Math.random() * total;
  let m = mix[0];
  for (const e of mix) {
    if ((x -= e[0]) < 0) {
      m = e;
      break;
    }
  }
  const res = http.get(BASE + m[3](data), params(m[1], m[2]));
  check(res, { "status 200": (r) => r.status === 200 });
}
