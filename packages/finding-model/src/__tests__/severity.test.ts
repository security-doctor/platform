import { describe, it, expect } from 'vitest';
import {
  baseSeverity, computePriority, computeSeverity, shiftSeverity,
  assertRuleEmittableConfidence, MAX_TOTAL_ADJUSTMENT,
} from '../severity.js';
import type { Exploitability, Impact, Severity } from '../types.js';

describe('severity matrix', () => {
  const cases: Array<[Impact, Exploitability, Severity]> = [
    ['catastrophic', 'trivial', 'critical'],
    ['catastrophic', 'theoretical', 'medium'],
    ['severe', 'trivial', 'critical'],
    ['severe', 'easy', 'high'],
    ['severe', 'conditional', 'medium'],
    ['moderate', 'trivial', 'high'],
    ['moderate', 'easy', 'medium'],
    ['minor', 'trivial', 'medium'],
    ['minor', 'theoretical', 'info'],
  ];

  it.each(cases)('%s x %s -> %s', (impact, exploitability, expected) => {
    expect(baseSeverity(impact, exploitability)).toBe(expected);
  });

  it('clamps total adjustment to one level in each direction', () => {
    const down = computeSeverity({
      impact: 'severe', exploitability: 'easy',
      adjustments: [
        { reason: 'not reachable', delta: -1 },
        { reason: 'dev dependency', delta: -2 },
      ],
    });
    expect(down.base).toBe('high');
    expect(down.severity).toBe('medium'); // not 'info'
    expect(MAX_TOTAL_ADJUSTMENT).toBe(1);
  });

  it('never lets a confirmed finding sit below high', () => {
    const r = computeSeverity({ impact: 'minor', exploitability: 'theoretical', verificationOutcome: 'confirmed' });
    expect(r.base).toBe('info');
    expect(r.severity).toBe('high');
  });

  it('drops a refuted finding to info regardless of base severity', () => {
    const r = computeSeverity({ impact: 'catastrophic', exploitability: 'trivial', verificationOutcome: 'refuted' });
    expect(r.severity).toBe('info');
    expect(r.adjustments[0]?.reason).toMatch(/Refuted/);
  });

  it('does not shift past the ends of the scale', () => {
    expect(shiftSeverity('critical', 5)).toBe('critical');
    expect(shiftSeverity('info', -5)).toBe('info');
  });
});

describe('priority', () => {
  it('ranks a confirmed high above a tentative critical', () => {
    const confirmedHigh = computePriority({ severity: 'high', confidence: 'confirmed' });
    const tentativeCritical = computePriority({ severity: 'critical', confidence: 'tentative' });
    expect(confirmedHigh).toBeGreaterThan(tentativeCritical);
  });

  it('zeroes a refuted finding', () => {
    expect(computePriority({ severity: 'critical', confidence: 'refuted' })).toBe(0);
  });

  it('stays within 0-100', () => {
    expect(computePriority({ severity: 'critical', confidence: 'confirmed', reachability: 1, recency: 1 })).toBe(100);
    expect(computePriority({ severity: 'info', confidence: 'tentative' })).toBeGreaterThanOrEqual(0);
  });
});

describe('confidence guard', () => {
  it.each(['confirmed', 'refuted'] as const)('forbids a rule emitting %s', (c) => {
    expect(() => assertRuleEmittableConfidence(c, 'SEC-AUTHZ-001')).toThrow(/Verification Engine/);
  });

  it.each(['firm', 'tentative'] as const)('allows a rule to emit %s', (c) => {
    expect(() => assertRuleEmittableConfidence(c, 'SEC-AUTHZ-001')).not.toThrow();
  });
});
