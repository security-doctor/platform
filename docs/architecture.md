# Architecture

Security Doctor finds security problems in TypeScript/Node web applications, **proves
which ones are real**, and proves when a fix worked. This document is what a contributor
needs to work on it. It deliberately contains no commercial detail.

## The problem this exists to solve

Static analysis cannot see authorization. It sees a route handler and a database query;
it cannot know whether the caller was allowed to run it. That is why most SAST tooling is
weak on Broken Access Control — the top OWASP category, and the one AI-assisted code gets
wrong most often.

We close that gap with a three-way join. No single signal is trustworthy; the conjunction
is:

```
  STATIC                RUNTIME                  BEHAVIOURAL
  Surface Map      +    Security Core       +    Differential test
  "this route           evidence                 "user B fetched
   reaches data         "0 authorization         user A's object
   with no authz        decisions recorded       and got 200 with
   check on any         for this route"          A's data"
   path"
       │                     │                        │
       └─────────────────────┴────────────────────────┘
                             ▼
                     CONFIRMED FINDING
```

## Components

| Package | What it does |
|---|---|
| `@security-doctor/evidence-schema` | Runtime evidence contract. Zero dependencies, no logic. |
| `@security-doctor/finding-model` | Canonical `Finding`: severity, confidence, fingerprinting, lifecycle, fail policy, SARIF. Zero dependencies. |
| `@security-doctor/surface-map` | Inventory of HTTP entry points and their authorization reachability. *(week 2–3)* |
| `@security-doctor/rules` | Detection logic, remediation prose, verification plans. *(week 3–5)* |
| `@security-doctor/core` + adapters | The runtime SDK: secure defaults, and the evidence emitter. *(week 7–8)* |
| `@security-doctor/verification-engine` | Turns findings into safe, bounded tests against an authorised target. *(week 9–10)* |
| `@security-doctor/cli` | Orchestration and developer experience. *(week 5–6)* |
| `dep-graph-check` | Enforces the architectural and repo invariants below, in CI. |

## The three intermediate representations

Everything is built on three data structures. Get these right and the rest is mechanical.

**1. Application Surface Map** — the static inventory of HTTP entry points: method,
normalised path pattern, parameters, handler symbol, reachable data access, and the
authentication/authorization checks found on any path from entry to data access. It
records what it could **not** resolve, explicitly — incompleteness lowers a finding's
confidence rather than being hidden.

**2. `Finding`** — the canonical output. Every component speaks this.

**3. `EvidenceRecord`** — what the SDK emits per request: which security decisions
actually executed. Joins to the Surface Map by `surfaceId`. That join is what turns a
static guess into a fact without sending any attack traffic.

## Dependency direction

Strictly acyclic, enforced by `pnpm check:deps`:

```
        evidence-schema        finding-model      (both zero-dependency contracts)
             ▲                       ▲
             │                       │
        security-core           surface-map
             ▲                       ▲
             │                       │
      core-next / core-express    rules
                                     ▲
                                     │
                                    cli
```

- `evidence-schema`, `finding-model` and `security-core` declare **zero** runtime and peer
  dependencies. `security-core` runs inside customers' production request paths; a
  transitive dependency there is a supply-chain liability we would own.
- `security-core` may not import any workspace package except `evidence-schema`.
- `verification-engine` may not import `rules` — it consumes data, so rule code never
  executes inside the process that talks to a live target.
- Nothing imports `cli`. It is an orchestrator, not a library.

## Invariants CI enforces

These are not style preferences. Each protects a property the product depends on.

| Invariant | Where |
|---|---|
| No dependency cycles; contract packages stay dependency-free | `tools/dep-graph-check` |
| No npm token, `_authToken` line, or private key anywhere in the tree | `repo-invariants.test.ts` |
| The reviewable `.security-doctor/` artifacts are never gitignored | `repo-invariants.test.ts` |
| Fingerprints survive reformatting and renames, and change when the sink changes | `fingerprint.test.ts` |
| A rule can never emit `confidence: 'confirmed'` | `assertRuleEmittableConfidence()` |
| A finding cannot reach `verified` without a prior confirmed verification | `lifecycle.ts` |

## Two rules that are not negotiable

**1. Only the Verification Engine may assert exploitability.** `confidence: 'confirmed'`
and `'refuted'` are engine-only. A rule that matched a pattern has found a *possibility*.
`assertRuleEmittableConfidence()` makes claiming otherwise a runtime error.

**2. Only proven findings fail a build.** `DEFAULT_FAIL_POLICY = 'verified'`. Confirmed
findings, exposed secrets and known-exploited critical dependencies block; everything else
is advisory. This is a promise to the developer, not a tunable default — a tool that
blocks on guesses gets `continue-on-error: true` within a month, and then it is decoration.

A corollary worth stating: a verification that can **refute** a finding is as valuable as
one that confirms. Refutation is how the tool reduces noise rather than producing it.

## Severity and confidence

Severity for code findings is `impact × exploitability`, adjusted by at most one level,
with every adjustment recorded so `--explain` can justify it. We do **not** compute CVSS
for code findings — CVSS scores a vulnerability with a known attack vector, which a source
pattern does not have until it is verified. CVSS is carried through verbatim for dependency
findings only.

Priority weights confidence, so a confirmed `high` outranks a tentative `critical`.

## Verification safety

The engine sends HTTP requests designed to demonstrate security failures. The safety gate
is the highest-criticality code in the repository and is built and adversarially tested
*before* anything that sends a real request.

- Active testing against any non-loopback target requires a committed, expiring **Target
  Authorization Record** with a human attestation.
- `environmentClass: production` is not a representable value. There is no override flag.
- One guarded HTTP client, resolve-then-connect with an IP allowlist, no cross-host
  redirects, bounded concurrency and request counts, abort on latency or error-rate
  degradation.
- Mutating tests require an ephemeral datastore; `DELETE` is only ever issued against
  objects the run itself created, tracked in a ledger. Residue is always reported.

## Working on it

```bash
pnpm install
pnpm check:all      # deps → typecheck → lint → test → build
pnpm test:watch
```

Node ≥ 20. pnpm workspaces, Turborepo, tsup, Vitest, Changesets.

Every rule ships with its lab case and fixtures in the same PR — including the near-miss
negatives. A rule without a negative fixture is not a rule.

## Standards

CWE and OWASP (Top 10 2021, API Security Top 10 2023) mappings are required on every rule.
We do not claim "full OWASP Top 10 coverage" — no tool has it, and the claim costs
credibility with exactly the people who can evaluate it. Coverage is stated per category,
honestly.
