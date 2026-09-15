import { describe, it, expect } from 'vitest';
import { validateFinding, assertValidFinding } from '../validate.js';
import { makeFinding } from './fixtures.js';

describe('finding validation', () => {
  it('accepts a well-formed finding', () => {
    expect(validateFinding(makeFinding())).toEqual([]);
  });

  it('requires a concrete impact statement', () => {
    const issues = validateFinding(makeFinding({ impact: '   ' }));
    expect(issues.map((i) => i.field)).toContain('impact');
  });

  it('requires at least one CWE and one reference', () => {
    const issues = validateFinding(makeFinding({ cwe: [], references: [] }));
    expect(issues.map((i) => i.field)).toEqual(expect.arrayContaining(['cwe', 'references']));
  });

  it('rejects confirmed confidence without a verification result', () => {
    const issues = validateFinding(makeFinding({ confidence: 'confirmed' }));
    expect(issues.map((i) => i.message).join(' ')).toMatch(/never assert exploitability/);
  });

  it('rejects a short suppression reason', () => {
    const issues = validateFinding(
      makeFinding({ suppression: { reason: 'nah', by: 'red', at: '2026-09-13T00:00:00.000Z', expiresAt: '2026-11-01T00:00:00.000Z', source: 'inline' } }),
    );
    expect(issues.map((i) => i.field)).toContain('suppression.reason');
  });

  it('surfaces an expired suppression', () => {
    const issues = validateFinding(
      makeFinding({ suppression: { reason: 'Tracked in ENG-4412 and scheduled', by: 'red', at: '2025-01-01T00:00:00.000Z', expiresAt: '2025-02-01T00:00:00.000Z', source: 'file' } }),
    );
    expect(issues.map((i) => i.message).join(' ')).toMatch(/expired/);
  });

  it('requires either a location or a package reference', () => {
    const f = makeFinding();
    const { location: _drop, ...rest } = f;
    const issues = validateFinding(rest as typeof f);
    expect(issues.map((i) => i.field)).toContain('location');
  });

  it('throws with every issue listed', () => {
    expect(() => assertValidFinding(makeFinding({ impact: '', cwe: [] }))).toThrow(/impact[\s\S]*cwe|cwe[\s\S]*impact/);
  });
});
