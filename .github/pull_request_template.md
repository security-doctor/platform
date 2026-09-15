## What changed

<!-- One or two sentences. -->

## Checklist

- [ ] Every bug fixed here has a permanent regression fixture (PRD §12.2)
- [ ] Any new rule ships with >= 3 positive and >= 3 negative fixtures, and a lab case
- [ ] Any new rule's detection logic was **authored from scratch** and is not derived from
      the Semgrep Registry or any other licence-restricted rule corpus (PRD §19.3)
- [ ] No new runtime dependency in `evidence-schema`, `finding-model` or `security-core`
- [ ] No new HTTP client outside the verification engine's single guarded client
- [ ] Public API changes are reflected in the api-extractor report
