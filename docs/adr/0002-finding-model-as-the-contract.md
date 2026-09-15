# ADR-0002: The Finding model is the contract, and it has zero dependencies

**Status:** accepted · **Date:** 2026-09-13 · **PRD:** §8.1, §10.2, §10.4

## Context

Five components produce or consume findings: the rule engine, the correlation stage, the
verification engine, the reporters, and eventually a platform backend. Without one
canonical shape, each pair grows its own adapter and the severity model drifts.

## Decision

`@security-doctor/finding-model` owns `Finding` and everything that operates on it:
severity computation, priority, structural fingerprinting, the lifecycle state machine,
the fail policy, validation, and SARIF export. It depends on nothing, imports no workspace
package, and knows nothing about rules, engines, or frameworks.

Two fields are required that most tools treat as optional:

- **`impact`** — the concrete consequence. A finding that cannot state one is not worth
  showing, and requiring it forces every rule author to justify the rule's existence.
- **`severityBasis`** — the impact/exploitability inputs and every adjustment. Every
  severity must be explainable by `--explain`. This is how we avoid the industry norm of
  unjustifiable severity labels.

## Consequences

- `finding-model` cannot use a schema library (Zod, Valibot). Validation is hand-written.
  That is a real cost, accepted to keep the dependency count at zero.
- Changing a fingerprint input is a breaking change that requires a migration entry, or a
  rule update mass-reopens every finding it touches.
- The future backend ingests this exact JSON. There is no separate "cloud model".

## What would change our mind

Nothing about the zero-dependency rule. If hand-written validation becomes a genuine
maintenance burden, generate it from the JSON Schema at build time rather than taking a
runtime dependency.
