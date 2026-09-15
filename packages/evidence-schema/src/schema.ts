/** JSON Schema (draft 2020-12) for the evidence stream. Published so third parties
 *  and the future platform can validate without reading our TypeScript. */

export const evidenceRecordJsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://security-doctor.dev/schemas/evidence-record-1.json',
  title: 'EvidenceRecord',
  type: 'object',
  required: ['v', 'ts', 'correlationId', 'method', 'routePattern', 'decisions', 'status', 'durationMs'],
  additionalProperties: false,
  properties: {
    v: { const: 1 },
    ts: { type: 'string', format: 'date-time' },
    correlationId: { type: 'string', minLength: 1, maxLength: 128 },
    upstreamCorrelationId: { type: 'string', maxLength: 128 },
    surfaceId: { type: 'string', maxLength: 512 },
    method: { type: 'string', maxLength: 16 },
    routePattern: { type: 'string', maxLength: 512 },
    identity: {
      type: 'object',
      required: ['subjectHash'],
      additionalProperties: false,
      properties: {
        subjectHash: { type: 'string', minLength: 16, maxLength: 128 },
        roles: { type: 'array', items: { type: 'string', maxLength: 64 }, maxItems: 32 },
      },
    },
    decisions: {
      type: 'array',
      maxItems: 64,
      items: {
        type: 'object',
        required: ['control', 'outcome'],
        additionalProperties: false,
        properties: {
          control: { enum: ['authn', 'authz', 'csrf', 'ratelimit', 'validation'] },
          policy: { type: 'string', maxLength: 128 },
          outcome: { enum: ['allow', 'deny', 'skip', 'error'] },
          durationMs: { type: 'number', minimum: 0 },
          at: {
            type: 'object',
            additionalProperties: false,
            properties: { file: { type: 'string', maxLength: 512 }, line: { type: 'integer', minimum: 0 } },
          },
        },
      },
    },
    status: { type: 'integer', minimum: 100, maximum: 599 },
    durationMs: { type: 'number', minimum: 0 },
    runTag: { type: 'string', maxLength: 128 },
    meta: {
      type: 'object',
      additionalProperties: { type: 'string', maxLength: 256 },
    },
  },
} as const;

export const bootRecordJsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://security-doctor.dev/schemas/evidence-boot-1.json',
  title: 'BootRecord',
  type: 'object',
  required: ['v', 'kind', 'ts', 'sdkVersion', 'defaultsPreset', 'controls', 'nodeEnv', 'runTag'],
  additionalProperties: false,
  properties: {
    v: { const: 1 },
    kind: { const: 'boot' },
    ts: { type: 'string', format: 'date-time' },
    sdkVersion: { type: 'string', maxLength: 32 },
    defaultsPreset: { type: 'string', pattern: '^\\d{4}-\\d{2}$' },
    controls: { type: 'array', items: { enum: ['authn', 'authz', 'csrf', 'ratelimit', 'validation'] } },
    nodeEnv: { type: 'string', maxLength: 32 },
    runTag: { type: 'string', maxLength: 128 },
  },
} as const;
