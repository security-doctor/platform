import type { FindingStatus, VerificationOutcome } from './types.js';

/**
 * Finding lifecycle — PRD §8.6.
 *
 * Two rules are load-bearing:
 *   1. `fixed -> verified` requires a PRIOR confirmed verification for the same
 *      fingerprint. Otherwise "fix verified" would mean "the pattern went away",
 *      which is not proof (D-9).
 *   2. Reopening raises severity by one level. A regression is worse than a new bug.
 */

const TRANSITIONS: Record<FindingStatus, readonly FindingStatus[]> = {
  detected: ['confirmed', 'acknowledged', 'false-positive', 'accepted-risk', 'not-applicable', 'fixed'],
  confirmed: ['acknowledged', 'fixed', 'accepted-risk', 'false-positive'],
  acknowledged: ['fixed', 'accepted-risk', 'not-applicable'],
  fixed: ['verified', 'closed', 'reopened'],
  verified: ['closed', 'reopened'],
  closed: ['reopened'],
  'false-positive': ['reopened', 'detected'],
  'accepted-risk': ['detected', 'acknowledged'],
  'not-applicable': ['detected'],
  reopened: ['detected', 'confirmed', 'acknowledged'],
};

export interface TransitionContext {
  /** True when a `confirmed` VerificationResult exists for this fingerprint at an earlier commit. */
  readonly hasPriorConfirmation?: boolean;
  /** Human-supplied transitions need a reason of >= 20 chars and an expiry (D-15). */
  readonly reason?: string;
  readonly expiresAt?: string;
  readonly actor?: 'engine' | 'human' | 'scanner';
}

export interface TransitionResult {
  readonly ok: boolean;
  readonly status: FindingStatus;
  readonly severityDelta: number;
  readonly error?: string;
}

const NEEDS_REASON: readonly FindingStatus[] = ['accepted-risk', 'not-applicable', 'false-positive'];

export function canTransition(from: FindingStatus, to: FindingStatus): boolean {
  return (TRANSITIONS[from] ?? []).includes(to);
}

export function transition(
  from: FindingStatus,
  to: FindingStatus,
  ctx: TransitionContext = {},
): TransitionResult {
  if (!canTransition(from, to)) {
    return { ok: false, status: from, severityDelta: 0, error: `Illegal transition ${from} -> ${to}` };
  }

  if (to === 'verified' && ctx.hasPriorConfirmation !== true) {
    return {
      ok: false,
      status: from,
      severityDelta: 0,
      error:
        'Cannot mark a finding verified without a prior confirmed verification for the same ' +
        'fingerprint. A missing code pattern is not proof that the vulnerability is gone.',
    };
  }

  if (to === 'confirmed' && ctx.actor !== 'engine') {
    return {
      ok: false,
      status: from,
      severityDelta: 0,
      error: 'Only the Verification Engine may move a finding to confirmed.',
    };
  }

  if (NEEDS_REASON.includes(to) && ctx.actor === 'human') {
    if ((ctx.reason ?? '').trim().length < 20) {
      return { ok: false, status: from, severityDelta: 0, error: `Status "${to}" requires a reason of at least 20 characters.` };
    }
    if (!ctx.expiresAt) {
      return { ok: false, status: from, severityDelta: 0, error: `Status "${to}" requires an expiry date (max 90 days).` };
    }
  }

  return { ok: true, status: to, severityDelta: to === 'reopened' ? 1 : 0 };
}

export function statusFromVerification(
  current: FindingStatus,
  outcome: VerificationOutcome,
): FindingStatus {
  switch (outcome) {
    case 'confirmed': return 'confirmed';
    case 'refuted': return 'false-positive';
    case 'fix-verified': return 'verified';
    case 'inconclusive':
    case 'refused':
    default: return current;
  }
}

export const MAX_SUPPRESSION_DAYS = 90;

export function suppressionExpiry(from: Date = new Date(), days = MAX_SUPPRESSION_DAYS): string {
  const capped = Math.min(days, MAX_SUPPRESSION_DAYS);
  return new Date(from.getTime() + capped * 86_400_000).toISOString();
}

export function isExpired(expiresAt: string, now: Date = new Date()): boolean {
  return new Date(expiresAt).getTime() <= now.getTime();
}
