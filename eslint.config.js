// ESLint flat config for qproof-tools (P2-5).
//
// Pragmatic ruleset for an already-strict TypeScript codebase: it should pass
// (close to) clean out of the box. We enable typescript-eslint's recommended
// set plus the two type-aware promise rules that matter most for the async
// MCP/HTTP/sieve transports (`no-floating-promises`, `no-misused-promises`),
// and deliberately turn OFF noisy stylistic / mass-failing rules so the lint
// is a real signal rather than a wall of churn.
//
// `projectService: true` gives the type-aware rules a TS program without us
// having to enumerate every tsconfig in the monorepo.

import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // Paths that should never be linted (build output, type decls, generated /
  // mock material). Keep this first so the ignores apply globally.
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/coverage/**",
      "**/*.d.ts",
      "**/examples/**", // mock SUT / sample vulnerable trees, intentionally "bad"
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  // Type-aware layer: the high-value promise-handling rules, applied only to
  // package SOURCE — the files a tsconfig project actually compiles. Scoping
  // projectService here avoids "file not found by the project service" errors
  // on test files / scripts, which no tsconfig includes (tests run via tsx).
  {
    files: ["packages/*/src/**/*.ts"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
    },
  },

  // Test files are not part of any tsconfig project — lint them syntactically
  // (recommended set), without the type-aware program.
  {
    files: ["packages/*/test/**/*.ts"],
    ...tseslint.configs.disableTypeChecked,
  },

  // Pragmatic relaxations: these would otherwise mass-fail or fight the
  // existing (deliberate, strict-TS) style. tsconfig already enforces
  // noUnusedLocals, so we let TS own unused-vars rather than double-reporting.
  {
    rules: {
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },

  // scripts/ are zero-dep Node utilities (not part of any tsconfig project);
  // lint them lightly without the type-aware program to avoid project errors.
  {
    files: ["scripts/**/*.{js,mjs,cjs}"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        performance: "readonly",
        structuredClone: "readonly",
        globalThis: "readonly",
      },
    },
  },
);
