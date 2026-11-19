import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Builds the graph render benchmark (bench/index.html) on its own; never part
// of the product bundle. Output: bench/dist (git-ignored).
export default defineConfig({
  root: __dirname,
  base: "./",
  plugins: [react(), tailwindcss()],
  define: { __PATHOS_BUNDLE_VERSION__: JSON.stringify("bench") },
  resolve: { alias: { "@": `${__dirname}/../src` } },
  build: { outDir: `${__dirname}/dist`, emptyOutDir: true, target: "es2022", sourcemap: false },
  worker: { format: "es" },
});
