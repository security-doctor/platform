# ADR-0001: Monorepo, pnpm, Turborepo, tsup, Vitest

**Status:** accepted · **Date:** 2026-09-13 · **PRD:** §10.3

## Context

Eight-plus packages that version independently: two zero-dependency contract packages, a
runtime SDK plus framework adapters, an analysis library, a rule pack, a verification
engine, and a CLI. The rule pack must ship weekly without a CLI release. The SDK must
work in ESM, CJS, and the Next.js Edge runtime.

## Decision

- **pnpm workspaces.** Strict `node_modules` prevents phantom dependencies. That matters
  more here than usual: we assert publicly that three packages have zero runtime
  dependencies, and a hoisted resolution that accidentally works would hide a violation.
- **Turborepo** for task orchestration and caching. Simple, remote-cacheable, right size.
- **tsup (esbuild)** for dual ESM/CJS output with declarations.
- **Vitest** for tests. TypeScript-native, fast, good fixture ergonomics.
- **Changesets** with independent versions.
- **Node >= 20 LTS.** AsyncLocalStorage maturity, native fetch, realistic for the ICP.
- **`ignore-scripts=true`** in `.npmrc`. A security vendor should not execute arbitrary
  install scripts, and neither should its CI.

## Consequences

- Contributors need `corepack enable pnpm`. Documented in the README.
- Turborepo's cache must never be shared across PR branches (PRD §9.5, cache poisoning).
- Edge-runtime compatibility is not free: the SDK must be tested in both runtimes, and
  `node:crypto` must be swapped for Web Crypto in edge paths.

## What would change our mind

If the SDK's dual-format output causes real-world resolution bugs for users, move
`security-core` to ESM-only and accept the CJS breakage. We would rather ship one correct
format than two subtly broken ones.
