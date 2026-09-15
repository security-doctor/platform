# @security-doctor/finding-model

The canonical `Finding` and everything that operates on it: the two-axis severity model,
the confidence model, structural fingerprinting, the lifecycle state machine, and
SARIF 2.1.0 export.

This is the contract every other package speaks. It is **zero-dependency** and knows
nothing about rules, engines or frameworks (PRD §10.2).

## The two rules that matter

1. **`confidence: 'confirmed'` may only be set by the Verification Engine.** No rule may
   emit it. `assertRuleEmittableConfidence()` enforces this at the boundary.
2. **Only confirmed findings fail a build.** See `DEFAULT_FAIL_POLICY` and PRD §8.4 — this
   is the product's trust contract, not a tunable default.
