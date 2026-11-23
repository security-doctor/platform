# Updates

A running log of where this project is and what has changed. If you are new here, read
this top to bottom once — especially **Traps we have already hit**, which is the part that
saves you time rather than just informing you.

For *how the system is designed*, read [`architecture.md`](./architecture.md) instead.
For *why* a structural decision was made, see [`adr/`](./adr/).

---

## Current state — 23 November 2026

| | |
|---|---|
| Default branch | `main` |
| Latest on `main` | `55578d2` — schema `$id` values moved off a registrable domain |
| Packages | `@security-doctor/finding-model` and `@security-doctor/evidence-schema`, both at `0.1.0` |
| Published to npm | **Not yet.** Versioned and ready; the release job is waiting on its first run |
| Tests | 115, all passing |
| Phase | Week 1 of the build order complete (contract packages, CI, architecture guards) |

Nothing in `packages/` beyond the two contract packages exists yet. That is on purpose —
the build order deliberately front-loads the contracts and the test corpus before any
detection logic.

---

## Getting running

```bash
corepack enable pnpm
pnpm install
pnpm check:all        # deps → typecheck → lint → test → build
pnpm test:watch       # while working
```

Node ≥ 20 and pnpm 10. `pnpm check:all` is what CI runs, so if it is green locally it is
green in CI.

**On Windows:** run pnpm from Windows directly, not from a Linux shell that has the folder
mounted. `node_modules` contains platform-native binaries and pnpm symlinks; the two
environments cannot share one install.

---

## What exists

| Package | Status | What it is |
|---|---|---|
| `@security-doctor/evidence-schema` | **built** | Runtime evidence contract: types + published JSON Schema. Zero dependencies, no logic. |
| `@security-doctor/finding-model` | **built** | Canonical `Finding`: severity, confidence, fingerprinting, lifecycle, fail policy, SARIF 2.1.0 export. Zero dependencies. |
| `dep-graph-check` | **built** | Enforces the architectural and repo invariants in CI. |
| `surface-map` | not started | Inventory of HTTP entry points and their authorization reachability. The core differentiator. |
| `rules` | not started | Detection logic, remediation prose, verification plans. |
| `core` + framework adapters | not started | The runtime SDK: secure defaults, and the evidence emitter. |
| `verification-engine` | not started | Turns findings into safe, bounded tests against an authorised target. |
| `cli` | not started | Orchestration and developer experience. |

---

## Decisions already made

These are settled. Each one has a reason that is not obvious from the code, so please read
the reason before proposing a change.

| Decision | Why |
|---|---|
| `confidence: 'confirmed'` may only be set by the Verification Engine | A rule that matched a pattern has found a *possibility*. `assertRuleEmittableConfidence()` makes claiming otherwise a runtime error. |
| Only proven findings fail a build (`DEFAULT_FAIL_POLICY = 'verified'`) | A tool that blocks on guesses gets `continue-on-error: true` within a month, and then it is decoration. This is a promise, not a tunable. |
| No CVSS for code findings | CVSS scores a vulnerability with a known attack vector. A source pattern has none until verified. Severity is `impact × exploitability`, adjusted by at most one level, every adjustment recorded. |
| Line numbers are never a fingerprint input | Putting them in is the common mistake in this class of tool and it makes baselines useless. Property tests pin reformat-invariance and sink-sensitivity. |
| Contract packages and the SDK carry zero runtime dependencies | The SDK runs in customers' production request paths. A transitive dependency there is a supply-chain liability we would own. Enforced in CI. |
| All detection rules are authored from scratch | See **Semgrep rule licensing** under Traps. This is a legal constraint, not a preference. |
| The safety gate is built and adversarially tested before anything that sends a request | The verification engine is the one component that can damage a customer's system. |
| Suppressions and baselines expire (90 days max, reason required) | Permanent suppression is how security debt becomes invisible. |
| Schema `$id` values point at GitHub Pages, not a domain | A domain that lapses can be re-registered by anyone, who would then control a URL our published packages point at. Pinned by test. |

---

## Open items

Roughly in order.

1. **First npm publish.** `0.1.0` is versioned and ready. The release job runs on pushes to
   `main`, gated by an environment that requires a human approval. First publish needs a
   short-lived npm token; see `.github/workflows/release.yml`, which also carries the
   instructions for removing it afterwards.
2. **Switch to trusted publishing and delete the token.** npm cannot use OIDC for a package
   that does not exist yet, so the token covers publish #1 only. Direct-publish granular
   tokens are removed by npm in January 2027, so this is mandatory, not hygiene.
3. **Make the schema `$id`s resolve.** Create a `security-doctor.github.io` repo in the org
   with a `schemas/` folder holding the two JSON files. The identifiers are stable either
   way — JSON Schema does not require `$id` to be dereferenceable — but resolving is better
   manners for integrators.
4. **Open product question, currently unanswered:** verification of access-control bugs
   needs at least two authenticated test identities, supplied by the developer as a small
   function. Whether real teams will write that is the assumption the strongest
   verification tier rests on. Until we have an answer from real users, treat the
   behavioural-differential tier as unproven and keep the runtime-evidence tier (which
   needs no attack traffic and no identities) as the primary story.
5. **Next build phase: the security lab.** Two realistic applications (Next.js App Router
   with Auth.js and Prisma; Express with Passport), seeded with three users and owned
   objects, plus the case-manifest format and the first case end to end. The lab comes
   *before* the Surface Map on purpose: it is the corpus every rule is measured against,
   and its fix-by-hand variant is what proves the tool detects real bugs rather than
   "didn't use our SDK".

---

## Traps we have already hit

Each of these cost real time. They are written down so they cost it once.

**`.gitignore` has no effect on a file git already tracks.**
Adding a path to `.gitignore` after the file has been committed changes nothing — `git add -A`
keeps staging it, and it survives a history rewrite. The fix is always
`git rm --cached <path>`, never another `.gitignore` line. There is now a test
(`repo-invariants.test.ts`) asserting `git ls-files -i -c --exclude-standard` is empty, so
the contradiction fails CI instead of being discovered by hand.

**CRLF produces diffs with no content in them.**
A Windows checkout without `.gitattributes` can rewrite whole files to CRLF, giving a diff
with equal insertion and deletion counts and zero real change. `git diff --ignore-all-space`
returning empty is the tell. Fixed by `.gitattributes` with `* text=auto eol=lf`.

**`changesets/action` v2 renamed its v1 inputs.**
`publish` → `publish-script`, `version` → `version-script`, and `GITHUB_TOKEN` moved from
env to a `github-token` input. v2 ignores unknown inputs *silently*, so the release job goes
green, publishes nothing, and opens no PR. Verify against the action's `action.yml` at the
pinned tag whenever you bump a major.

**npm provenance cannot be generated locally.**
It requires GitHub Actions or GitLab CI on a cloud-hosted runner, plus a `repository` field
in `package.json` that matches the publishing source *case-sensitively*. A local
`npm publish` with provenance enabled fails. This is intentional here — the release path is
CI-only by design.

**npm trusted publishing cannot do a package's first publish.**
It is configured per package on npmjs.com, which requires the package to exist. Acknowledged
upstream as an MVP scope limitation. So: token → publish → configure trusted publishers →
delete token.

**Changesets needs an org-level permission to open its version PR.**
*Allow GitHub Actions to create and approve pull requests* is off by default for
organizations, and the repository-level control is greyed out when an org policy is set.
Without it the action fails to open the version PR. The workaround, which needs no
permission: run `pnpm changeset version` locally, commit, and push — with no pending
changesets the action enters publish mode directly.

**Semgrep rule licensing.**
The Semgrep CE engine is LGPL-2.1 and fine to invoke as a separate process. But rules in the
**Semgrep Registry** are licensed for internal business use only and explicitly forbid
vendors from using them in competing products or SaaS offerings; some third-party registry
rules are AGPL-3.0. **Never ship, bundle, or derive a rule from the registry.** Every rule
PR carries an attestation that its detection logic was authored from scratch. Opengrep (an
LGPL-2.1 fork) is the preferred bundled engine for the same reason.

**SARIF upload to code scanning needs GitHub Code Security on private repositories.**
Most of the teams this product is for will not have it. Check runs and a single sticky PR
comment are therefore the primary surface; SARIF is best-effort and must never fail a build
when the upload is rejected.

**Environment protection rules are public-repository-only on Free/Pro/Team.**
"Required reviewers" simply does not appear in the UI on a private repo — it is not hidden,
it is not offered.

**Pin actions by commit SHA, and resolve the SHA rather than recalling it.**
`git ls-remote --tags --refs https://github.com/<owner>/<repo>` gives tag → SHA. Never copy
a SHA from memory or a blog post. We tell users to pin; shipping unpinned ourselves would
not be credible.

---

## Working agreements

- **Every rule ships with its lab case and fixtures in the same PR**, including the
  near-miss negatives. A rule without a negative fixture is not a rule.
- **A guard nobody has watched fail is just a comment.** Every invariant test in this repo
  was verified by deliberately breaking the condition, watching the test fail, and fixing
  it. Do the same for new ones.
- **Report what you did not check.** Coverage lines, unresolved call-graph edges, degraded
  engines — surfaced, never hidden. An honest gap beats a silent one.
- **Never claim "secure".** A clean scan means "no findings above medium", and the output
  says so.

---

## Log

**23 November 2026** — Added `.gitattributes` to normalise line endings (a Windows checkout
had produced a 269-line phantom diff). Moved both schema `$id` values off
`security-doctor.dev` and onto GitHub Pages, and pinned them by test: a permanent identifier
should not depend on a renewable domain. Added the ignored-but-tracked repo invariant. This
file created.

**22 November 2026** — Resumed after a pause. Verified the live repo, registry and DNS state
rather than assuming. Confirmed the September cleanup had worked: no strategy documents or
stray archives in the tree. Found and re-added a repo invariant that had not made it into a
commit.

**15 September 2026** — Repository made public. Routed vulnerability disclosure through
GitHub private advisories rather than an email address at a domain not yet owned. Added
`architecture.md` as the contributor-facing design document. Added credential-hygiene
invariants. Versioned both packages to `0.1.0`.

**13–14 September 2026** — Week 1 of the build order: monorepo, `finding-model` (severity,
priority, structural fingerprinting, lifecycle, fail policy, SARIF), `evidence-schema`,
`dep-graph-check`, CI and the release pipeline, ADRs 0001–0004. Settled naming on the
`@security-doctor` npm scope and the `security-doctor` GitHub org.

---

## Where things live

| | |
|---|---|
| Code, ADRs, this file | this repository |
| Contributor-facing design | [`architecture.md`](./architecture.md) |
| Disclosure policy | [`SECURITY.md`](../SECURITY.md) |
| Product requirements and commercial planning | **not in this repository** — maintainers' document store. This repo is public; those documents are not. |
| Published packages | `@security-doctor` on npm |
