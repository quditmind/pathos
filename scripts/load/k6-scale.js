// PATHOS scale test (docs/PERFORMANCE.md): the main read paths against a
// large dataset (scripts/load/loadgen.sh seed). Run through
// scripts/load/scale.sh, which signs in and passes the session cookie.
//
// SCENARIO selects the run:
//   sweep  - one virtual user calls every endpoint ITER times in turn:
//            per-endpoint latency without contention (ep_* trends);
//   mixed  - a weighted mix at a constant arrival rate (RATE req/s for
//            DURATION): throughput and errors under load;
//   users  - USERS concurrent users, each clicking through pages with a
//            1-3 s think time, ramped up over RAMP and held for DURATION.
import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

const BASE = __ENV.PATHOS_URL || "https://localhost";
const COOKIE = __ENV.PATHOS_COOKIE;
const SCENARIO = __ENV.SCENARIO || "sweep";
const ITER = Number(__ENV.ITER || 20);
const RATE = Number(__ENV.RATE || 20);
const DURATION = __ENV.DURATION || "60s";
const USERS = Number(__ENV.USERS || 50);
const RAMP = __ENV.RAMP || "30s";
const ONLY = (__ENV.ONLY || "").split(",").filter(Boolean);

const pick = (a) => a[Math.floor(Math.random() * a.length)];
const enc = encodeURIComponent;

// [name, weight in the mixed scenario, request(data) -> [method, path, body]]
const endpoints = [
  ["findings_list", 14, () => ["GET", "/api/v1/findings"]],
  ["findings_sort_risk", 5, () => ["GET", "/api/v1/findings?sort=risk"]],
  ["findings_severity_category", 6, () => ["GET", `/api/v1/findings?severity=critical,high&category=${pick(["sca", "sast", "secrets"])}`]],
  ["findings_by_repository", 5, (d) => ["GET", `/api/v1/findings?repository_id=${pick(d.repos)}`]],
  ["findings_big_repository", 2, (d) => ["GET", `/api/v1/findings?repository_id=${d.bigRepo}&status=all`]],
  ["findings_text_search", 4, () => ["GET", `/api/v1/findings?q=${pick(["injection", "CVE-2019-10", "credential", "pkg-12", "module7/"])}`]],
  ["findings_status_all", 3, () => ["GET", "/api/v1/findings?status=all"]],
  ["findings_page_5", 3, (d) => ["GET", `/api/v1/findings?cursor=${enc(d.cursor5)}`]],
  ["findings_lifecycle_new", 2, () => ["GET", "/api/v1/findings?lifecycle=new"]],
  ["findings_kev", 2, () => ["GET", "/api/v1/findings?kev=true"]],
  ["findings_sla_breached", 3, () => ["GET", "/api/v1/findings?sla=breached"]],
  ["findings_by_application", 2, (d) => ["GET", `/api/v1/findings?application_id=${pick(d.apps)}`]],
  ["findings_summary", 8, () => ["GET", "/api/v1/findings/summary"]],
  ["finding_detail", 8, (d) => ["GET", `/api/v1/findings/${pick(d.ids)}`]],
  ["finding_history", 3, (d) => ["GET", `/api/v1/findings/${pick(d.ids)}/history`]],
  ["finding_risk", 2, (d) => ["GET", `/api/v1/findings/${pick(d.ids)}/risk`]],
  ["dashboard_30d", 6, () => ["GET", "/api/v1/dashboard"]],
  ["dashboard_365d", 1, () => ["GET", "/api/v1/dashboard?days=365"]],
  ["executive", 1, () => ["GET", "/api/v1/executive"]],
  ["posture_aggregate", 2, () => ["GET", "/api/v1/posture/aggregate"]],
  ["posture_applications", 2, () => ["GET", "/api/v1/posture/applications"]],
  ["posture_coverage", 1, () => ["GET", "/api/v1/posture/coverage"]],
  ["global_search", 3, () => ["GET", `/api/v1/search?q=${pick(["service-1", "payments", "loadgen-app-4", "identity/service-77"])}`]],
  ["repositories_list", 4, () => ["GET", "/api/v1/repositories?limit=50"]],
  ["repositories_search", 2, () => ["GET", `/api/v1/repositories?limit=50&q=${pick(["service-12", "data", "web/service-9"])}`]],
  ["repository_detail", 2, (d) => ["GET", `/api/v1/repositories/${pick(d.repos)}`]],
  ["sbom_components", 2, () => ["GET", "/api/v1/sbom/components"]],
  ["sbom_license_violations", 1, () => ["GET", "/api/v1/sbom/components?license=violations"]],
  ["scans_list", 2, () => ["GET", "/api/v1/scans"]],
  ["report_run_json", 1, (d) => ["GET", `/api/v1/reports/${d.report}/run`]],
  ["export_report_csv", 1, (d) => ["GET", `/api/v1/reports/${d.report}/run?format=csv`]],
  ["export_sbom_spdx", 1, (d) => ["GET", `/api/v1/repositories/${d.bigRepo}/sbom?format=spdx`]],
  ["report_group_by_repository", 1, () => ["POST", "/api/v1/reports/preview", { group_by: "repository", filters: {} }]],
].filter((e) => ONLY.length === 0 || ONLY.includes(e[0]));

const trends = {};
const failed = {};
for (const e of endpoints) {
  trends[e[0]] = new Trend(`ep_${e[0]}`, true);
  failed[e[0]] = new Rate(`fail_${e[0]}`);
}

const scenarios = {
  sweep: { executor: "shared-iterations", vus: 1, iterations: endpoints.length * ITER, maxDuration: "60m" },
  mixed: { executor: "constant-arrival-rate", rate: RATE, timeUnit: "1s", duration: DURATION, preAllocatedVUs: 50, maxVUs: 400 },
  users: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: RAMP, target: USERS },
      { duration: DURATION, target: USERS },
    ],
    gracefulRampDown: "10s",
  },
};

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: { [SCENARIO]: scenarios[SCENARIO] },
  summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max", "count"],
  thresholds: { http_req_failed: ["rate<0.01"] },
  setupTimeout: "300s",
};

function headers(csrf) {
  const h = { Cookie: COOKIE, Accept: "application/json" };
  if (csrf) {
    h["X-CSRF-Token"] = csrf;
    h["Content-Type"] = "application/json";
  }
  return h;
}

export function setup() {
  const get = (p) => {
    const r = http.get(BASE + p, { headers: headers(), tags: { name: "setup" }, timeout: "300s" });
    if (r.status !== 200) throw new Error(`${p}: HTTP ${r.status} ${r.body}`);
    return r.json();
  };
  const me = get("/api/v1/me");
  // Finding ids from several pages, and the cursor of page 5.
  let ids = [];
  let cursor = null;
  let cursor5 = null;
  for (let i = 0; i < 4; i++) {
    const page = get("/api/v1/findings?status=all" + (cursor ? `&cursor=${enc(cursor)}` : ""));
    ids = ids.concat(page.items.map((f) => f.id));
    cursor = page.next_cursor;
  }
  cursor = null;
  for (let i = 0; i < 4; i++) cursor = get("/api/v1/findings" + (cursor ? `?cursor=${enc(cursor)}` : "")).next_cursor;
  cursor5 = cursor;
  const repos = get("/api/v1/repositories?limit=200").items.map((x) => x.id);
  const apps = (get("/api/v1/applications").items || []).map((x) => x.id).slice(0, 100);
  // The synthetic repository with the most findings (loadgen power law).
  const bigRepo = "0000000b-0000-7000-8001-000000000001";
  const rep = http.post(
    BASE + "/api/v1/reports",
    JSON.stringify({ name: `scale test ${Date.now()}`, definition: { filters: { severity: "critical,high" } } }),
    { headers: headers(me.csrf_token), tags: { name: "setup" } },
  );
  if (rep.status !== 201 && rep.status !== 200) throw new Error(`create report: HTTP ${rep.status} ${rep.body}`);
  return { ids, cursor5, repos, apps, bigRepo, report: rep.json("id"), csrf: me.csrf_token };
}

function call(d, e) {
  const [method, path, body] = e[2](d);
  const params = { headers: headers(method === "GET" ? null : d.csrf), tags: { name: e[0] }, timeout: "120s" };
  const res = method === "GET" ? http.get(BASE + path, params) : http.request(method, BASE + path, JSON.stringify(body), params);
  const ok = res.status >= 200 && res.status < 300;
  trends[e[0]].add(res.timings.duration);
  failed[e[0]].add(!ok);
  check(res, { "status 2xx": () => ok });
  return res;
}

const total = endpoints.reduce((s, e) => s + e[1], 0);
function weighted() {
  let x = Math.random() * total;
  for (const e of endpoints) if ((x -= e[1]) < 0) return e;
  return endpoints[0];
}

// A user session: the pages a security engineer opens in turn.
const journey = [
  ["dashboard_30d"],
  ["findings_list", "findings_summary"],
  ["findings_severity_category", "findings_summary"],
  ["finding_detail", "finding_history"],
  ["findings_by_repository"],
  ["findings_text_search"],
  ["repositories_list"],
  ["global_search"],
  ["findings_page_5"],
  ["posture_aggregate"],
];
const byName = Object.fromEntries(endpoints.map((e) => [e[0], e]));

let sweepIndex = 0;
export default function (d) {
  if (SCENARIO === "sweep") {
    call(d, endpoints[Math.floor(sweepIndex++ / ITER) % endpoints.length]);
    return;
  }
  if (SCENARIO === "mixed") {
    call(d, weighted());
    return;
  }
  for (const page of journey) {
    for (const n of page) if (byName[n]) call(d, byName[n]);
    sleep(1 + Math.random() * 2);
  }
}

export function teardown(d) {
  http.del(`${BASE}/api/v1/reports/${d.report}`, null, { headers: headers(d.csrf), tags: { name: "setup" } });
}
