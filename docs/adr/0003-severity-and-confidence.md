# ADR-0003: Two-axis severity, and confidence that changes behaviour

**Status:** accepted · **Date:** 2026-09-13 · **PRD:** §8.3, §8.4 (decisions D-13, D-14)

## Context

Every SAST tool on the market attaches CVSS scores to source-code findings. CVSS scores a
vulnerability in a deployed product with a known attack vector and complexity. A pattern
in source code has neither until it is verified. Producing `7.5` for a maybe is false
precision, and developers can tell.

Separately: tools fail builds on unproven findings, developers lose trust, and within a
month the job carries `continue-on-error: true`. At that point the tool is decoration.

## Decision

**Severity** for code findings is `impact × exploitability`, adjusted by at most one level
in either direction, with every adjustment recorded and printable. CVSS is carried through
verbatim for dependency findings only, where it is meaningful.

**Confidence** is a first-class field with four values, and it changes behaviour:

| Confidence | Set by | CI behaviour |
|---|---|---|
| `confirmed` | Verification Engine only | Fails the build |
| `firm` | A rule, when analysis fully resolved | Advisory |
| `tentative` | A rule, by default | Advisory, collapsed in the report |
| `refuted` | Verification Engine only | Hidden, retained with evidence |

`assertRuleEmittableConfidence()` makes it a runtime error for a rule to claim
`confirmed`. **Only proven findings fail a build** is the product's public promise, and
`DEFAULT_FAIL_POLICY = 'verified'` is where it lives in code.

Priority weights confidence, so a confirmed `high` outranks a tentative `critical`.

## Consequences

- Early on, very little will fail a build, because verification coverage is narrow. That
  is correct. A tool that blocks rarely and is right every time beats the reverse.
- We cannot market "OWASP Top 10 coverage" numbers derived from CVSS. Good.
- Customers who want severity-based gating can set `fail-on: high`, and we tell them what
  that trades away.

## What would change our mind

If design partners report that nothing ever blocks and therefore nothing ever gets fixed,
the answer is more verification coverage — not a looser default.
