/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import pkg from "./package.json" with { type: "json" };

// The bundle version (frontend/package.json) is compared at run time with the
// backend version from GET /api/v1/meta to offer a reload after an upgrade.

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: { __PATHOS_BUNDLE_VERSION__: JSON.stringify(pkg.version) },
  resolve: { alias: { "@": "/src" } },
  build: { sourcemap: false, target: "es2022" },
  // The graph layout worker (ELK) is an ES module worker.
  worker: { format: "es" },
  server: {
    // The Help Center bundles Markdown from ../docs.
    fs: { allow: [".."] },
    // `npm run dev` against a running stack: proxy API and Keycloak.
    proxy: {
      "/api": { target: "https://localhost", changeOrigin: false, secure: false },
      "/auth": { target: "https://localhost", changeOrigin: false, secure: false },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    css: false,
  },
});
