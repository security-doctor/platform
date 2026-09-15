import {
  SEVERITY_ORDER,
  severityRank,
  type Confidence,
  type Exploitability,
  type Impact,
  type Severity,
  type SeverityAdjustment,
  type SeverityBasis,
} from './types.js';

/**
 * Two-axis severity for code findings — PRD §8.3 / D-13.
 *
 * We deliberately do NOT compute CVSS for code findings. CVSS scores a vulnerability in a
 * deployed product with known attack vector and complexity; a source pattern has neither
 * until it is verified. CVSS is carried through verbatim for dependency findings only.
 */
const MATRIX: Record<Impact, Record<Exploitability, Severity>> = {
  catastrophic: { trivial: 'critical', easy: 'critical', conditional: 'high',   theoretical: 'medium' },
  severe:       { trivial: 'critical', easy: 'high',     conditional: 'medium', theoretical: 'low' },
  moderate:     { trivial: 'high',     easy: 'medium',   conditional: 'medium', theoretical: 'low' },
  minor:        { trivial: 'medium',   easy: 'low',      conditional: 'low',    theoretical: 'info' },
};

/** Total adjustment is clamped to +/- 1 level so a pile of small modifiers cannot swamp the matrix. */
export const MAX_TOTAL_ADJUSTMENT = 1;

export function baseSeverity(impact: Impact, exploitability: Exploitability): Severity {
  return MATRIX[impact][exploitability];
}

export function shiftSeverity(severity: Severity, delta: number): Severity {
  const next = Math.min(SEVERITY_ORDER.length - 1, Math.max(0, severityRank(severity) + delta));
  return SEVERITY_ORDER[next] as Severity;
}

export interface SeverityInput {
  readonly impact: Impact;
  readonly exploitability: Exploitability;
  readonly adjustments?: readonly SeverityAdjustment[];
  readonly verificationOutcome?: 'confirmed' | 'refuted' | 'fix-verified' | 'inconclusive' | 'refused';
}

export function computeSeverity(input: SeverityInput): SeverityBasis & { severity: Severity } {
  const base = baseSeverity(input.impact, input.exploitability);
  const adjustments = [...(input.adjustments ?? [])];

  // Verification dominates every other adjustment (PRD §8.3).
  if (input.verificationOutcome === 'refuted') {
    const refuted: SeverityAdjustment = { reason: 'Refuted by verification', delta: -99 };
    return { impact: input.impact, exploitability: input.exploitability, base, adjustments: [refuted], severity: 'info' };
  }
  if (input.verificationOutcome === 'confirmed') {
    adjustments.push({ reason: 'Confirmed by verification', delta: 1 });
    const raised = shiftSeverity(base, 1);
    // A confirmed finding is never below `high`: it is a demonstrated vulnerability.
    const severity = severityRank(raised) < severityRank('high') ? 'high' : raised;
    return { impact: input.impact, exploitability: input.exploitability, base, adjustments, severity };
  }

  const raw = adjustments.reduce((sum, a) => sum + a.delta, 0);
  const clamped = Math.min(MAX_TOTAL_ADJUSTMENT, Math.max(-MAX_TOTAL_ADJUSTMENT, raw));
  return {
    impact: input.impact,
    exploitability: input.exploitability,
    base,
    adjustments,
    severity: shiftSeverity(base, clamped),
  };
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 1.0, high: 0.75, medium: 0.45, low: 0.2, info: 0.05,
};

/**
 * Confidence weighting is what makes a confirmed `high` outrank a tentative `critical`.
 * That ordering is the visible expression of the trust contract (PRD §8.3).
 */
const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  confirmed: 1.0, firm: 0.8, tentative: 0.45, refuted: 0.0,
};

export interface PriorityInput {
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** Is the finding reachable from a public entry point? Unknown defaults to 0.85. */
  readonly reachability?: number;
  /** 1.0 for a finding introduced by the current change, decaying for older ones. */
  readonly recency?: number;
}

export function computePriority(input: PriorityInput): number {
  const weight =
    SEVERITY_WEIGHT[input.severity] *
    CONFIDENCE_WEIGHT[input.confidence] *
    (input.reachability ?? 0.85) *
    (input.recency ?? 1);
  return Math.round(Math.min(1, Math.max(0, weight)) * 100);
}

/** Only the Verification Engine may set these (PRD §8.4 / D-14). */
export const ENGINE_ONLY_CONFIDENCE: readonly Confidence[] = ['confirmed', 'refuted'];

export function assertRuleEmittableConfidence(c: Confidence, ruleId: string): void {
  if (ENGINE_ONLY_CONFIDENCE.includes(c)) {
    throw new Error(
      `Rule ${ruleId} attempted to emit confidence "${c}". ` +
        'Only the Verification Engine may set confirmed/refuted — a rule can never prove exploitability.',
    );
  }
}
