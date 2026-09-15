import { describe, it, expect } from 'vitest';
import { canTransition, transition, statusFromVerification, suppressionExpiry, isExpired, MAX_SUPPRESSION_DAYS } from '../lifecycle.js';

describe('lifecycle', () => {
  it('allows the happy path', () => {
    expect(canTransition('detected', 'confirmed')).toBe(true);
    expect(canTransition('confirmed', 'fixed')).toBe(true);
    expect(canTransition('fixed', 'verified')).toBe(true);
    expect(canTransition('verified', 'closed')).toBe(true);
  });

  it('rejects illegal jumps', () => {
    expect(canTransition('detected', 'verified')).toBe(false);
    expect(canTransition('closed', 'fixed')).toBe(false);
  });

  it('refuses to mark verified without a prior confirmation', () => {
    const r = transition('fixed', 'verified', { actor: 'engine' });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not proof/);
  });

  it('allows verified when a prior confirmation exists', () => {
    const r = transition('fixed', 'verified', { actor: 'engine', hasPriorConfirmation: true });
    expect(r.ok).toBe(true);
  });

  it('only lets the engine confirm', () => {
    expect(transition('detected', 'confirmed', { actor: 'human' }).ok).toBe(false);
    expect(transition('detected', 'confirmed', { actor: 'engine' }).ok).toBe(true);
  });

  it('requires a reason and an expiry for human risk acceptance', () => {
    expect(transition('detected', 'accepted-risk', { actor: 'human', reason: 'later' }).ok).toBe(false);
    expect(transition('detected', 'accepted-risk', { actor: 'human', reason: 'Tracked in ENG-4412, fixing next sprint' }).ok).toBe(false);
    expect(
      transition('detected', 'accepted-risk', {
        actor: 'human',
        reason: 'Tracked in ENG-4412, fixing next sprint',
        expiresAt: suppressionExpiry(),
      }).ok,
    ).toBe(true);
  });

  it('raises severity by one level on reopen', () => {
    const r = transition('closed', 'reopened', { actor: 'scanner' });
    expect(r.ok).toBe(true);
    expect(r.severityDelta).toBe(1);
  });

  it.each([
    ['confirmed', 'confirmed'],
    ['refuted', 'false-positive'],
    ['fix-verified', 'verified'],
  ] as const)('maps verification %s to status %s', (outcome, expected) => {
    expect(statusFromVerification('detected', outcome)).toBe(expected);
  });

  it('leaves status untouched for inconclusive and refused outcomes', () => {
    expect(statusFromVerification('detected', 'inconclusive')).toBe('detected');
    expect(statusFromVerification('confirmed', 'refused')).toBe('confirmed');
  });

  it('caps suppression expiry at 90 days', () => {
    const expiry = new Date(suppressionExpiry(new Date('2026-01-01T00:00:00Z'), 365));
    const max = new Date('2026-01-01T00:00:00Z').getTime() + MAX_SUPPRESSION_DAYS * 86400000;
    expect(expiry.getTime()).toBe(max);
  });

  it('detects expiry', () => {
    expect(isExpired('2020-01-01T00:00:00.000Z')).toBe(true);
    expect(isExpired(suppressionExpiry())).toBe(false);
  });
});
