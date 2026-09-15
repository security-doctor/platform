/**
 * Runtime evidence contract (PRD §4.2, §5.6.6).
 *
 * A single `EvidenceRecord` describes the security decisions that actually executed
 * for one request. The `surfaceId` field is the join key back to the static
 * Application Surface Map — that join is what upgrades a static guess to a
 * confirmed finding without sending any attack traffic.
 *
 * Privacy invariants enforced by the emitter, not by this package:
 *   - no raw identifiers (subjects are HMAC'd with a per-process key)
 *   - no cookie, authorization or token values
 *   - no request or response bodies
 */

export const EVIDENCE_SCHEMA_VERSION = 1 as const;

export type SecurityControl =
  | 'authn'
  | 'authz'
  | 'csrf'
  | 'ratelimit'
  | 'validation';

export type DecisionOutcome = 'allow' | 'deny' | 'skip' | 'error';

export interface DecisionSite {
  readonly file?: string;
  readonly line?: number;
}

export interface SecurityDecision {
  readonly control: SecurityControl;
  /** Registered policy name, e.g. "document:read". Absent for controls without policies. */
  readonly policy?: string;
  readonly outcome: DecisionOutcome;
  readonly at?: DecisionSite;
  /** Milliseconds spent inside the decision, for budget tracking. */
  readonly durationMs?: number;
}

export interface EvidenceSubject {
  /** HMAC-SHA256 of the subject id under a per-process ephemeral key. Never the raw id. */
  readonly subjectHash: string;
  /** Coarse role labels only. Never free-form user attributes. */
  readonly roles?: readonly string[];
}

export interface EvidenceRecord {
  readonly v: typeof EVIDENCE_SCHEMA_VERSION;
  /** ISO 8601 timestamp. */
  readonly ts: string;
  /** Server-generated. An inbound X-Correlation-Id is never trusted as this value. */
  readonly correlationId: string;
  /** Untrusted, recorded for tracing only. */
  readonly upstreamCorrelationId?: string;
  /** Join key to SurfaceEntry.id, e.g. "next:app:GET /api/documents/[id]". */
  readonly surfaceId?: string;
  readonly method: string;
  /** Normalised route pattern, e.g. "/api/documents/:id". Never the concrete URL. */
  readonly routePattern: string;
  readonly identity?: EvidenceSubject;
  readonly decisions: readonly SecurityDecision[];
  readonly status: number;
  readonly durationMs: number;
  /** Per-run HMAC so forged or stale records can be rejected (PRD §13.2). */
  readonly runTag?: string;
  /** Redacted, truncated free-form annotations. Max 256 bytes per value. */
  readonly meta?: Readonly<Record<string, string>>;
}

/** Emitted once at boot, as the first line of the evidence stream (PRD §5.6.5). */
export interface BootRecord {
  readonly v: typeof EVIDENCE_SCHEMA_VERSION;
  readonly kind: 'boot';
  readonly ts: string;
  readonly sdkVersion: string;
  /** The dated defaults preset in force, e.g. "2026-09". */
  readonly defaultsPreset: string;
  readonly controls: readonly SecurityControl[];
  readonly nodeEnv: string;
  readonly runTag: string;
}

export type EvidenceStreamRecord = BootRecord | EvidenceRecord;

export function isBootRecord(r: EvidenceStreamRecord): r is BootRecord {
  return (r as BootRecord).kind === 'boot';
}

export function isEvidenceRecord(r: EvidenceStreamRecord): r is EvidenceRecord {
  return (r as BootRecord).kind !== 'boot';
}

/**
 * Structural guard for records parsed from NDJSON written by another process.
 * Deliberately shallow: the Verification Engine treats evidence as untrusted input
 * and re-validates the fields it relies on.
 */
export function looksLikeEvidenceRecord(value: unknown): value is EvidenceRecord {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    r['v'] === EVIDENCE_SCHEMA_VERSION &&
    typeof r['ts'] === 'string' &&
    typeof r['correlationId'] === 'string' &&
    typeof r['method'] === 'string' &&
    typeof r['routePattern'] === 'string' &&
    typeof r['status'] === 'number' &&
    typeof r['durationMs'] === 'number' &&
    Array.isArray(r['decisions'])
  );
}
