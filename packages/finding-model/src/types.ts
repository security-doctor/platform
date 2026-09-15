/** Canonical Finding model — PRD §8.1. */

export const FINDING_SCHEMA_VERSION = 1 as const;

export type Category =
  | 'access-control' | 'authentication' | 'session' | 'injection' | 'xss'
  | 'ssrf' | 'csrf' | 'cryptography' | 'secrets' | 'dependency'
  | 'configuration' | 'file-handling' | 'api-design' | 'logging'
  | 'availability' | 'supply-chain';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** PRD §8.4. `confirmed` and `refuted` are settable only by the Verification Engine. */
export type Confidence = 'confirmed' | 'firm' | 'tentative' | 'refuted';

export type Impact = 'catastrophic' | 'severe' | 'moderate' | 'minor';
export type Exploitability = 'trivial' | 'easy' | 'conditional' | 'theoretical';

export type FindingStatus =
  | 'detected' | 'confirmed' | 'acknowledged' | 'fixed' | 'verified' | 'closed'
  | 'false-positive' | 'accepted-risk' | 'not-applicable' | 'reopened';

export type RuleKind = 'pattern' | 'type-aware' | 'config' | 'engine-backed' | 'runtime';
export type RuleStage = 'experimental' | 'advisory' | 'stable';

export interface OwaspMapping {
  readonly top10_2021?: readonly string[];
  readonly api2023?: readonly string[];
}

export interface Location {
  /** Repo-relative, POSIX separators, always. */
  readonly path: string;
  readonly startLine: number;
  readonly startColumn?: number;
  readonly endLine?: number;
  readonly endColumn?: number;
  /** Enclosing export/function path, e.g. "GET" or "handlers.updateUser". Used in fingerprinting. */
  readonly symbol?: string;
  /** At most 5 lines, secrets redacted. */
  readonly snippet?: string;
}

export interface PackageRef {
  readonly name: string;
  readonly version: string;
  readonly ecosystem: 'npm';
  readonly direct: boolean;
  readonly scope: 'prod' | 'dev' | 'optional';
  /** Path from a direct dependency to this package. */
  readonly dependencyPath: readonly string[];
}

export interface DataFlowStep {
  readonly step: string;
  readonly location: Location;
}

export interface Evidence {
  readonly kind: 'code' | 'config' | 'dependency' | 'secret' | 'runtime' | 'behavioural';
  /** One sentence: what was actually observed. */
  readonly summary: string;
  readonly dataFlow?: readonly DataFlowStep[];
  readonly observed?: Readonly<Record<string, unknown>>;
  readonly expected?: Readonly<Record<string, unknown>>;
  readonly redacted: boolean;
}

export interface Remediation {
  /** Imperative, one sentence. */
  readonly summary: string;
  readonly steps: readonly string[];
  readonly codeExample?: { readonly language: string; readonly before: string; readonly after: string };
  readonly sdkFix?: { readonly package: string; readonly snippet: string };
  readonly effort: 'trivial' | 'small' | 'medium' | 'large';
  readonly breakingChangeRisk: 'none' | 'low' | 'medium' | 'high';
}

export type VerificationTier = 0 | 1 | 2 | 3 | 4;

export type Precondition =
  | { readonly kind: 'target-class'; readonly allowed: readonly TargetClass[] }
  | { readonly kind: 'identities'; readonly count: number; readonly roles?: readonly string[] }
  | { readonly kind: 'sdk-evidence'; readonly minRecords: number }
  | { readonly kind: 'mutation-allowed' }
  | { readonly kind: 'ephemeral-datastore' };

export type TargetClass = 'local' | 'ci' | 'staging';

export interface VerificationDescriptor {
  readonly available: boolean;
  readonly tier: VerificationTier;
  readonly requires: readonly Precondition[];
  /** Exact copy-pasteable command. */
  readonly command: string;
  /** What the test will do, in plain language, shown before it runs. */
  readonly description: string;
}

export type VerificationOutcome =
  | 'confirmed' | 'refuted' | 'fix-verified' | 'inconclusive' | 'refused';

export interface VerificationResult {
  readonly fingerprint: string;
  readonly outcome: VerificationOutcome;
  readonly tier: VerificationTier;
  readonly confidence: 'high' | 'medium' | 'low';
  /** Always present, always a human sentence. */
  readonly reason: string;
  readonly ranAt: string;
  readonly targetFingerprint: string;
  readonly toolVersions: Readonly<Record<string, string>>;
  readonly cleanupComplete: boolean;
  /** Objects the run could not remove. Must be surfaced to the user. */
  readonly residue?: readonly string[];
  readonly evidencePath?: string;
}

export type DetectionSource =
  | { readonly engine: 'pattern'; readonly tool: string; readonly toolVersion: string }
  | { readonly engine: 'type-aware'; readonly analyzer: string }
  | { readonly engine: 'config' }
  | { readonly engine: 'sca'; readonly tool: 'osv'; readonly databaseVersion: string }
  | { readonly engine: 'secrets'; readonly tool: string; readonly toolVersion: string }
  | { readonly engine: 'runtime'; readonly sdkVersion: string }
  | { readonly engine: 'correlation'; readonly inputs: readonly string[] };

export interface Reference {
  readonly title: string;
  readonly url: string;
}

export interface SeverityAdjustment {
  readonly reason: string;
  /** Levels moved. Negative lowers severity. */
  readonly delta: number;
}

export interface SeverityBasis {
  readonly impact: Impact;
  readonly exploitability: Exploitability;
  readonly adjustments: readonly SeverityAdjustment[];
  /** Severity before adjustments were applied. */
  readonly base: Severity;
}

export interface Suppression {
  /** At least 20 characters. Enforced by validateFinding(). */
  readonly reason: string;
  readonly by: string;
  readonly at: string;
  /** Mandatory. At most 90 days out (PRD §8.6 / D-15). */
  readonly expiresAt: string;
  readonly source: 'inline' | 'file' | 'baseline' | 'auto-refuted';
}

export interface Finding {
  readonly schemaVersion: typeof FINDING_SCHEMA_VERSION;

  readonly fingerprint: string;
  readonly id: string;
  readonly ruleId: string;
  readonly ruleVersion: string;

  readonly title: string;
  readonly description: string;
  readonly category: Category;
  readonly cwe: readonly string[];
  readonly owasp: OwaspMapping;
  readonly asvs?: readonly string[];

  readonly severity: Severity;
  readonly severityBasis: SeverityBasis;
  readonly confidence: Confidence;
  readonly status: FindingStatus;
  /** 0-100. The single sort key shown to users. */
  readonly priority: number;

  readonly location?: Location;
  readonly relatedLocations: readonly Location[];
  readonly surfaceId?: string;
  readonly package?: PackageRef;

  readonly evidence: Evidence;
  /** Concrete consequence. Required — a finding that cannot state one is not worth showing. */
  readonly impact: string;
  readonly remediation: Remediation;
  readonly verification?: VerificationDescriptor;
  readonly verificationResult?: VerificationResult;

  readonly detectionSource: DetectionSource;
  readonly references: readonly Reference[];
  readonly firstSeen: string;
  readonly lastSeen: string;
  readonly firstSeenCommit?: string;

  readonly suppression?: Suppression;
  readonly baselined?: { readonly since: string; readonly reason: string; readonly expiresAt: string };
  readonly tags: readonly string[];
}

export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function compareBySeverity(a: Severity, b: Severity): number {
  return severityRank(b) - severityRank(a);
}
