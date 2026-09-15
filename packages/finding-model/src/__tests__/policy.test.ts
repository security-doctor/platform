import { describe, it, expect } from 'vitest';
import { decideExit, isBlocking, DEFAULT_FAIL_POLICY, countBySeverity } from '../policy.js';
import { makeFinding } from './fixtures.js';
import type { VerificationResult } from '../types.js';

const verification: VerificationResult = {
  fingerprint: 'abcdefghijklmnopqrstuvwxyz',
  outcome: 'confirmed',
  tier: 3,
  confidence: 'high',
  reason: 'bob read a document owned by alice',
  ranAt: '2026-09-13T00:00:00.000Z',
  targetFingerprint: 'local',
  toolVersions: {},
  cleanupComplete: true,
};

describe('the trust contract', () => {
  it('defaults to blocking only on verified findings', () => {
    expect(DEFAULT_FAIL_POLICY).toBe('verified');
  });

  it('does not block on a tentative critical', () => {
    const f = makeFinding({ severity: 'critical', confidence: 'tentative' });
    expect(isBlocking(f, 'verified')).toBe(false);
  });

  it('does not block on a firm high', () => {
    const f = makeFinding({ severity: 'high', confidence: 'firm' });
    expect(isBlocking(f, 'verified')).toBe(false);
  });

  it('blocks on a confirmed finding', () => {
    const f = makeFinding({ confidence: 'confirmed', verificationResult: verification, status: 'confirmed' });
    expect(isBlocking(f, 'verified')).toBe(true);
  });

  it('blocks on an exposed secret even without verification', () => {
    const f = makeFinding({ category: 'secrets', severity: 'critical', confidence: 'firm' });
    expect(isBlocking(f, 'verified')).toBe(true);
  });

  it('blocks on a known-exploited critical dependency', () => {
    const f = makeFinding({ category: 'dependency', severity: 'critical', confidence: 'firm', tags: ['kev'] });
    expect(isBlocking(f, 'verified')).toBe(true);
  });

  it('never blocks on a refuted finding', () => {
    const f = makeFinding({ confidence: 'refuted', severity: 'critical', category: 'secrets' });
    expect(isBlocking(f, 'verified')).toBe(false);
  });

  it('never blocks on a suppressed or baselined finding', () => {
    const suppressed = makeFinding({
      confidence: 'confirmed', verificationResult: verification,
      suppression: { reason: 'Accepted, tracked in ENG-1', by: 'red', at: '2026-09-13T00:00:00.000Z', expiresAt: '2026-12-01T00:00:00.000Z', source: 'file' },
    });
    expect(isBlocking(suppressed, 'verified')).toBe(false);
  });
});

describe('new-findings-only behaviour', () => {
  const preexisting = makeFinding({ fingerprint: 'old', severity: 'critical', confidence: 'firm', category: 'secrets' });
  const introduced = makeFinding({ fingerprint: 'new', severity: 'critical', confidence: 'firm', category: 'secrets' });
  const ctx = { newFingerprints: new Set(['new']) };

  it('ignores pre-existing debt', () => {
    expect(isBlocking(preexisting, 'high', ctx)).toBe(false);
  });

  it('blocks on what this change introduced', () => {
    expect(isBlocking(introduced, 'high', ctx)).toBe(true);
  });

  it('still blocks on a pre-existing CONFIRMED finding', () => {
    const proven = makeFinding({ fingerprint: 'old', confidence: 'confirmed', verificationResult: verification });
    expect(isBlocking(proven, 'verified', ctx)).toBe(true);
  });
});

describe('exit decision', () => {
  it('exits 0 when nothing blocks', () => {
    const d = decideExit([makeFinding({ severity: 'high', confidence: 'firm' })]);
    expect(d.code).toBe(0);
  });

  it('exits 1 and explains why', () => {
    const d = decideExit([makeFinding({ confidence: 'confirmed', verificationResult: verification })]);
    expect(d.code).toBe(1);
    expect(d.reason).toMatch(/verified as exploitable/);
  });

  it('never fails on the none policy', () => {
    const d = decideExit([makeFinding({ confidence: 'confirmed', verificationResult: verification })], 'none');
    expect(d.code).toBe(0);
  });

  it('counts by severity', () => {
    const counts = countBySeverity([makeFinding({ severity: 'high' }), makeFinding({ severity: 'high' }), makeFinding({ severity: 'low' })]);
    expect(counts).toMatchObject({ high: 2, low: 1, critical: 0 });
  });
});
