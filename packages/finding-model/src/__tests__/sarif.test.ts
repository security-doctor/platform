import { describe, it, expect } from 'vitest';
import { toSarif } from '../sarif.js';
import { makeFinding } from './fixtures.js';

type SarifLog = {
  version: string;
  runs: Array<{
    tool: { driver: { name: string; version: string; rules: Array<Record<string, any>> } };
    results: Array<Record<string, any>>;
  }>;
};

const options = { toolVersion: '0.1.0', rulesPackVersion: '2026.9.1' };

describe('SARIF export', () => {
  it('emits a 2.1.0 log with the tool driver populated', () => {
    const log = toSarif([makeFinding()], options) as SarifLog;
    expect(log.version).toBe('2.1.0');
    expect(log.runs[0]?.tool.driver.name).toBe('Security Doctor');
    expect(log.runs[0]?.tool.driver.version).toBe('0.1.0');
  });

  it('deduplicates rules and indexes results into them', () => {
    const log = toSarif([makeFinding({ fingerprint: 'a' }), makeFinding({ fingerprint: 'b' })], options) as SarifLog;
    expect(log.runs[0]?.tool.driver.rules).toHaveLength(1);
    expect(log.runs[0]?.results).toHaveLength(2);
    expect(log.runs[0]?.results[0]?.['ruleIndex']).toBe(0);
  });

  it('maps severity to level and carries confidence as precision', () => {
    const log = toSarif([makeFinding({ severity: 'high', confidence: 'firm' })], options) as SarifLog;
    expect(log.runs[0]?.results[0]?.['level']).toBe('error');
    expect(log.runs[0]?.tool.driver.rules[0]?.['properties'].precision).toBe('high');
  });

  it('uses the structural fingerprint as the partial fingerprint so GitHub tracks alerts across moves', () => {
    const log = toSarif([makeFinding({ fingerprint: 'stable-id' })], options) as SarifLog;
    expect(log.runs[0]?.results[0]?.['partialFingerprints']).toEqual({ structural: 'stable-id' });
  });

  it('omits suppressed and baselined findings from results but keeps the rule metadata', () => {
    const log = toSarif(
      [makeFinding({ baselined: { since: '2026-01-01', reason: 'pre-existing', expiresAt: '2026-12-01' } })],
      options,
    ) as SarifLog;
    expect(log.runs[0]?.results).toHaveLength(0);
    expect(log.runs[0]?.tool.driver.rules).toHaveLength(1);
  });

  it('includes the verify command in rule help when verification is available', () => {
    const f = makeFinding({
      verification: {
        available: true, tier: 3, requires: [],
        command: 'security-doctor verify SEC-AUTHZ-001',
        description: 'Creates an object as user A, then attempts to read it as user B.',
      },
    });
    const log = toSarif([f], options) as SarifLog;
    expect(log.runs[0]?.tool.driver.rules[0]?.['help'].markdown).toContain('security-doctor verify SEC-AUTHZ-001');
  });

  it('tags CWE and OWASP mappings', () => {
    const log = toSarif([makeFinding()], options) as SarifLog;
    const tags = log.runs[0]?.tool.driver.rules[0]?.['properties'].tags as string[];
    expect(tags).toContain('external/cwe/cwe-639');
    expect(tags).toContain('owasp/A01');
    expect(tags).toContain('owasp-api/API1');
  });

  it('serialises to JSON without cycles or undefined keys', () => {
    const json = JSON.stringify(toSarif([makeFinding()], options));
    expect(json).not.toContain('undefined');
    expect(() => JSON.parse(json)).not.toThrow();
  });
});
