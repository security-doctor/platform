# @security-doctor/finding-model

## 0.1.0

### Minor Changes

- 80f4033: Initial release of the two contract packages.

  `finding-model` carries the canonical `Finding` type, the two-axis severity model,
  structural fingerprinting, the lifecycle state machine, the default fail policy
  (only proven findings block a build) and SARIF 2.1.0 export.

  `evidence-schema` carries the runtime `EvidenceRecord` contract emitted by Security
  Core and consumed by the Verification Engine, plus its published JSON Schema.

  Both declare zero runtime dependencies, enforced in CI.
