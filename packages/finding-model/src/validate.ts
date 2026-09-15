import { isExpired, MAX_SUPPRESSION_DAYS } from './lifecycle.js';
import type { Finding } from './types.js';

export interface ValidationIssue {
  readonly field: string;
  readonly message: string;
}

/**
 * Structural validation of a Finding before it leaves the pipeline.
 *
 * Two checks here are unusual and deliberate (PRD §8.1.2):
 *   - `impact` is required. A finding that cannot state a concrete consequence is not
 *     worth showing, and requiring it forces rule authors to justify every rule.
 *   - `severityBasis` is required. Every severity must be explainable by `--explain`.
 */
export function validateFinding(f: Finding): readonly ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const require = (cond: boolean, field: string, message: string) => {
    if (!cond) issues.push({ field, message });
  };

  require(f.schemaVersion === 1, 'schemaVersion', 'Unsupported schema version.');
  require(f.fingerprint.length > 0, 'fingerprint', 'Fingerprint is required.');
  require(f.ruleId.length > 0, 'ruleId', 'Rule id is required.');
  require(f.ruleVersion.length > 0, 'ruleVersion', 'Rule version is required.');
  require(f.title.length > 0 && f.title.length <= 80, 'title', 'Title must be 1-80 characters.');
  require(f.description.trim().length > 0, 'description', 'Description is required.');
  require(f.cwe.length > 0, 'cwe', 'At least one CWE mapping is required.');
  require(f.impact.trim().length > 0, 'impact', 'Impact is required: state the concrete consequence.');
  require(f.references.length > 0, 'references', 'At least one reference is required.');
  require(f.remediation.summary.trim().length > 0, 'remediation.summary', 'Remediation summary is required.');
  require(f.remediation.steps.length > 0, 'remediation.steps', 'At least one remediation step is required.');
  require(f.priority >= 0 && f.priority <= 100, 'priority', 'Priority must be 0-100.');
  require(
    f.location !== undefined || f.package !== undefined,
    'location',
    'A finding must have either a code location or a package reference.',
  );

  if (f.suppression) {
    require(f.suppression.reason.trim().length >= 20, 'suppression.reason', 'Suppression reason must be at least 20 characters.');
    require(Boolean(f.suppression.expiresAt), 'suppression.expiresAt', `Suppressions must expire within ${MAX_SUPPRESSION_DAYS} days.`);
    if (f.suppression.expiresAt && isExpired(f.suppression.expiresAt)) {
      issues.push({ field: 'suppression.expiresAt', message: 'Suppression has expired; the finding must be re-surfaced.' });
    }
  }

  if (f.confidence === 'confirmed' && !f.verificationResult) {
    issues.push({
      field: 'confidence',
      message: 'confidence "confirmed" requires a VerificationResult. Rules may never assert exploitability.',
    });
  }

  return issues;
}

export function assertValidFinding(f: Finding): void {
  const issues = validateFinding(f);
  if (issues.length > 0) {
    throw new Error(
      `Invalid finding ${f.ruleId} (${f.fingerprint}):\n` +
        issues.map((i) => `  - ${i.field}: ${i.message}`).join('\n'),
    );
  }
}
