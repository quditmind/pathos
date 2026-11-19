// ESLint configuration of the PATHOS worker-sast image: the recommended
// rules of eslint-plugin-security on JavaScript and TypeScript files.
// Dependencies, build output and minified bundles are not linted.
import security from "eslint-plugin-security";
import tsParser from "@typescript-eslint/parser";

export default [
  {
    ignores: ["**/node_modules/**", "**/.git/**", "**/dist/**", "**/build/**", "**/vendor/**", "**/coverage/**", "**/*.min.js", "**/*.bundle.js"],
  },
  {
    files: ["**/*.{js,cjs,mjs,jsx}"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module", parserOptions: { ecmaFeatures: { jsx: true } } },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    ...security.configs.recommended,
  },
  {
    files: ["**/*.{ts,cts,mts,tsx}"],
    languageOptions: { parser: tsParser, ecmaVersion: "latest", sourceType: "module", parserOptions: { ecmaFeatures: { jsx: true } } },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    plugins: security.configs.recommended.plugins,
    rules: security.configs.recommended.rules,
  },
];
