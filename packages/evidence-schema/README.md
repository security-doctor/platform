# @security-doctor/evidence-schema

The contract between **Security Core** (which emits runtime security decisions) and the
**Verification Engine** (which consumes them to upgrade static findings to confirmed).

This package is deliberately **zero-dependency** and contains **no logic** — only types,
a JSON Schema, and narrow type guards. See PRD §4.2 and §10.2.

Nothing in this package may import anything.
