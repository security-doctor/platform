import type { Finding } from '../types.js';

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const base: Finding = {
    schemaVersion: 1,
    fingerprint: 'abcdefghijklmnopqrstuvwxyz',
    id: 'SEC-AUTHZ-001#1',
    ruleId: 'SEC-AUTHZ-001',
    ruleVersion: '1.0.0',
    title: 'Document read without an ownership check',
    description: 'This route is authenticated but performs no ownership check.',
    category: 'access-control',
    cwe: ['CWE-639'],
    owasp: { top10_2021: ['A01'], api2023: ['API1'] },
    severity: 'high',
    severityBasis: { impact: 'severe', exploitability: 'easy', adjustments: [], base: 'high' },
    confidence: 'firm',
    status: 'detected',
    priority: 60,
    location: { path: 'app/api/documents/[id]/route.ts', startLine: 12, symbol: 'GET' },
    relatedLocations: [],
    surfaceId: 'next:app:GET /api/documents/[id]',
    evidence: { kind: 'code', summary: 'Handler queries document by request parameter with no ownership check.', redacted: false },
    impact: 'Any authenticated user can read any document by supplying a different identifier.',
    remediation: {
      summary: 'Check that the authenticated subject is permitted to access the loaded object.',
      steps: ['Load the object, then compare its owner to the session subject.'],
      effort: 'small',
      breakingChangeRisk: 'low',
    },
    detectionSource: { engine: 'type-aware', analyzer: 'surface-map' },
    references: [{ title: 'CWE-639', url: 'https://cwe.mitre.org/data/definitions/639.html' }],
    firstSeen: '2026-09-13T00:00:00.000Z',
    lastSeen: '2026-09-13T00:00:00.000Z',
    tags: [],
  };
  return { ...base, ...overrides };
}
