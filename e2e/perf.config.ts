import { defineConfig } from "@playwright/test";

// ADR-005 graph render benchmark: no stack, no sign-in. Serves the benchmark
// build (frontend/bench/dist, mounted at /bench by scripts/graph-bench.sh).
export default defineConfig({
  testDir: "./perf",
  timeout: 30 * 60_000,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: { baseURL: "http://127.0.0.1:4799", viewport: { width: 1440, height: 900 }, trace: "off", screenshot: "off" },
  webServer: { command: "node perf/serve.mjs /bench 4799", url: "http://127.0.0.1:4799/index.html", reuseExistingServer: false, timeout: 30_000 },
});
