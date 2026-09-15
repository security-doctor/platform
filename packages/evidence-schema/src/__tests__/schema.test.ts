import { describe, it, expect } from 'vitest';
import {
  EVIDENCE_SCHEMA_VERSION,
  evidenceRecordJsonSchema,
  bootRecordJsonSchema,
  isBootRecord,
  looksLikeEvidenceRecord,
  type EvidenceRecord,
  type BootRecord,
} from '../index.js';

const record: EvidenceRecord = {
  v: 1,
  ts: '2026-09-13T08:00:00.000Z',
  correlationId: '0192f0c1-0000-7000-8000-000000000000',
  surfaceId: 'next:app:GET /api/documents/[id]',
  method: 'GET',
  routePattern: '/api/documents/:id',
  identity: { subjectHash: 'a'.repeat(64), roles: ['user'] },
  decisions: [{ control: 'authn', outcome: 'allow' }, { control: 'authz', policy: 'document:read', outcome: 'deny' }],
  status: 403,
  durationMs: 4.2,
};

describe('evidence-schema', () => {
  it('pins the schema version', () => {
    expect(EVIDENCE_SCHEMA_VERSION).toBe(1);
    expect(evidenceRecordJsonSchema.properties.v.const).toBe(1);
  });

  it('accepts a well-formed record', () => {
    expect(looksLikeEvidenceRecord(record)).toBe(true);
  });

  it.each([
    ['null', null],
    ['a string', 'nope'],
    ['a wrong version', { ...record, v: 2 }],
    ['a missing routePattern', { ...record, routePattern: undefined }],
    ['non-array decisions', { ...record, decisions: 'authz' }],
  ])('rejects %s', (_label, value) => {
    expect(looksLikeEvidenceRecord(value)).toBe(false);
  });

  it('distinguishes boot records', () => {
    const boot: BootRecord = {
      v: 1, kind: 'boot', ts: record.ts, sdkVersion: '0.1.0',
      defaultsPreset: '2026-09', controls: ['authn', 'authz', 'csrf'],
      nodeEnv: 'test', runTag: 'run-1',
    };
    expect(isBootRecord(boot)).toBe(true);
    expect(isBootRecord(record)).toBe(false);
  });

  it('forbids additional properties in the published schema', () => {
    expect(evidenceRecordJsonSchema.additionalProperties).toBe(false);
    expect(bootRecordJsonSchema.additionalProperties).toBe(false);
  });
});
