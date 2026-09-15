import { severityRank, type Finding, type Severity } from './types.js';

/**
 * The trust contract — PRD §8.4 / D-14.
 *
 * "We will never fail your build on a guess."
 *
 * Only findings that were PROVEN, plus exposed secrets and known-exploited critical
 * dependency vulnerabilities, are blocking by default. This is the single policy that
 * decides whether a team keeps the tool or sets `continue-on-error: true`.
 */

export type FailPolicy = 'verified' | 'high' | 'none';

export const DEFAULT_FAIL_POLICY: FailPolicy = 'verified';

export interface FailPolicyContext {
  /** Findings introduced by the change under review. Pre-existing findings never block. */
  readonly newFingerprints?: ReadonlySet<string>;
}

export function isBlocking(finding: Finding, policy: FailPolicy, ctx: FailPolicyContext = {}): boolean {
  if (policy === 'none') return false;
  if (finding.suppression || finding.baselined) return false;
  if (finding.confidence === 'refuted') return false;
  if (finding.status === 'false-positive' || finding.status === 'accepted-risk') return false;

  // Pre-existing debt never blocks a PR; without this, adoption on any existing codebase is zero.
  if (ctx.newFingerprints && !ctx.newFingerprints.has(finding.fingerprint)) {
    // Confirmed findings are the exception: a proven vulnerability blocks wherever it came from.
    if (finding.confidence !== 'confirmed') return false;
  }

  if (finding.confidence === 'confirmed') return true;
  if (finding.category === 'secrets' && severityRank(finding.severity) >= severityRank('high')) return true;
  if (finding.tags.includes('kev') && finding.severity === 'critical') return true;

  if (policy === 'high') {
    return severityRank(finding.severity) >= severityRank('high');
  }
  return false;
}

export interface ExitDecision {
  readonly code: 0 | 1;
  readonly blocking: readonly Finding[];
  readonly reason: string;
}

export function decideExit(
  findings: readonly Finding[],
  policy: FailPolicy = DEFAULT_FAIL_POLICY,
  ctx: FailPolicyContext = {},
): ExitDecision {
  const blocking = findings.filter((f) => isBlocking(f, policy, ctx));
  if (blocking.length === 0) {
    return { code: 0, blocking, reason: 'No blocking findings.' };
  }
  const confirmed = blocking.filter((f) => f.confidence === 'confirmed').length;
  const reason =
    confirmed > 0
      ? `${confirmed} finding(s) were verified as exploitable.`
      : `${blocking.length} finding(s) exceeded the "${policy}" fail policy.`;
  return { code: 1, blocking, reason };
}

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}
