/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": "/src" } },
  build: { sourcemap: false, target: "es2022" },
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
