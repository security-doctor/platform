# Security Policy

This is a security product. We hold ourselves to the standard we ask of our users.

## Reporting a vulnerability

**Use [GitHub private vulnerability reporting](https://github.com/security-doctor/platform/security/advisories/new)** — the "Report a vulnerability" button on this
repository's Security tab. It is private, it reaches the maintainers directly, and it
needs no email address on either side.

Please do not open a public issue.

Include: what you found, where, how to reproduce it, and what you think the impact is.
If you have a proof of concept, attach it.

## What you can expect

| | |
|---|---|
| Acknowledgement | within 2 business days |
| Initial assessment | within 5 business days |
| Fix or mitigation plan | within 30 days for high/critical |
| Public disclosure | coordinated, within 90 days of the report |

## Safe harbour

We will not pursue legal action against anyone who reports a vulnerability to us in good
faith, provided you: do not access, modify or exfiltrate data belonging to anyone else;
do not degrade our services or our users' services; give us reasonable time to remediate
before public disclosure; and do not test against a customer's system without that
customer's written authorisation.

## Scope

In scope: everything in this repository, our published npm packages, our GitHub Actions,
and our documentation site.

Out of scope: the deliberately vulnerable applications in `security-lab/`. Those exist to
be insecure. They are `private: true`, bind to loopback only, and must never be deployed.

## Our own commitments

- Contract packages (`evidence-schema`, `finding-model`) and the runtime SDK
  (`security-core`) carry **zero runtime dependencies**, enforced in CI.
- All packages are published with npm provenance from a protected environment.
- The CLI makes no network calls except to the OSV advisory API, and sends only package
  names and versions.
- No telemetry. Nothing about your code leaves your machine.
