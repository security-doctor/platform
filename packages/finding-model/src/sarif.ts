import { severityRank, type Finding, type Severity } from './types.js';

/**
 * SARIF 2.1.0 export — PRD §9.6.
 *
 * Note: uploading SARIF to GitHub code scanning requires GitHub Code Security /
 * Advanced Security on private repositories, which most of our ICP will not have.
 * SARIF is therefore a bonus surface; check runs and the PR comment are primary (D-19).
 */

export interface SarifOptions {
  readonly toolName?: string;
  readonly toolVersion: string;
  readonly informationUri?: string;
  readonly rulesPackVersion?: string;
}

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

function level(severity: Severity): SarifLevel {
  if (severityRank(severity) >= severityRank('high')) return 'error';
  if (severity === 'medium') return 'warning';
  if (severity === 'low') return 'note';
  return 'none';
}

/** SARIF's rank is 0-100 with higher = more severe, which matches our priority field. */
function rank(f: Finding): number {
  return Math.max(0, Math.min(100, f.priority));
}

export function toSarif(findings: readonly Finding[], options: SarifOptions): unknown {
  const byRule = new Map<string, Finding>();
  for (const f of findings) if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, f);

  const rules = [...byRule.values()].map((f) => ({
    id: f.ruleId,
    name: f.ruleId.replace(/-/g, ''),
    shortDescription: { text: f.title },
    fullDescription: { text: f.description },
    help: {
      text: [f.impact, '', f.remediation.summary, ...f.remediation.steps.map((s) => `- ${s}`)].join('\n'),
      markdown: [
        `**Impact.** ${f.impact}`,
        '',
        `**Fix.** ${f.remediation.summary}`,
        ...f.remediation.steps.map((s) => `- ${s}`),
        ...(f.verification?.available ? ['', `**Prove it:** \`${f.verification.command}\``] : []),
      ].join('\n'),
    },
    defaultConfiguration: { level: level(f.severity) },
    properties: {
      tags: [
        f.category,
        ...f.cwe.map((c) => `external/cwe/${c.toLowerCase()}`),
        ...(f.owasp.top10_2021 ?? []).map((o) => `owasp/${o}`),
        ...(f.owasp.api2023 ?? []).map((o) => `owasp-api/${o}`),
      ],
      precision: sarifPrecision(f),
      'security-severity': securitySeverity(f.severity),
    },
  }));

  const ruleIndex = new Map([...byRule.keys()].map((id, i) => [id, i]));

  const results = findings
    .filter((f) => !f.suppression && !f.baselined)
    .map((f) => ({
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
      level: level(f.severity),
      rank: rank(f),
      message: { text: `${f.title}. ${f.evidence.summary}` },
      locations: f.location ? [physicalLocation(f.location)] : [],
      relatedLocations: f.relatedLocations.map((l, i) => ({ id: i, ...physicalLocation(l) })),
      partialFingerprints: { structural: f.fingerprint },
      properties: {
        confidence: f.confidence,
        status: f.status,
        priority: f.priority,
        ...(f.verificationResult ? { verification: f.verificationResult.outcome } : {}),
      },
    }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: options.toolName ?? 'Security Doctor',
            version: options.toolVersion,
            informationUri: options.informationUri ?? 'https://github.com/security-doctor/platform',
            ...(options.rulesPackVersion ? { semanticVersion: options.rulesPackVersion } : {}),
            rules,
          },
        },
        results,
      },
    ],
  };
}

function physicalLocation(l: { path: string; startLine: number; startColumn?: number; endLine?: number; endColumn?: number }) {
  return {
    physicalLocation: {
      artifactLocation: { uri: l.path, uriBaseId: '%SRCROOT%' },
      region: {
        startLine: l.startLine,
        ...(l.startColumn === undefined ? {} : { startColumn: l.startColumn }),
        ...(l.endLine === undefined ? {} : { endLine: l.endLine }),
        ...(l.endColumn === undefined ? {} : { endColumn: l.endColumn }),
      },
    },
  };
}

function sarifPrecision(f: Finding): 'very-high' | 'high' | 'medium' | 'low' {
  switch (f.confidence) {
    case 'confirmed': return 'very-high';
    case 'firm': return 'high';
    case 'tentative': return 'medium';
    case 'refuted': return 'low';
  }
}

/** GitHub reads this to bucket alerts. We map from our own model, never from CVSS. */
function securitySeverity(s: Severity): string {
  switch (s) {
    case 'critical': return '9.5';
    case 'high': return '7.5';
    case 'medium': return '5.0';
    case 'low': return '3.0';
    case 'info': return '0.0';
  }
}
