/**
 * Architectural constraints from PRD §4.3 and §10.4.
 *
 * These are not style preferences. Each one protects a property the product depends on:
 *   - contract packages stay dependency-free so the SDK can never drag a transitive
 *     dependency into a customer's production request path;
 *   - security-core stays framework-agnostic so adapters stay thin;
 *   - verification-engine cannot import rules, so plans are built from data, not rule code;
 *   - nothing imports the CLI, so the CLI stays an orchestrator with no logic worth reusing.
 */

export const WORKSPACE_SCOPE = '@security-doctor/';

/** Packages that must declare no runtime or peer dependencies at all. */
export const ZERO_DEPENDENCY_PACKAGES: readonly string[] = [
  '@security-doctor/evidence-schema',
  '@security-doctor/finding-model',
  '@security-doctor/core',
];

export interface ForbiddenEdge {
  readonly from: string;
  /** Exact package name, or a prefix ending in '*'. */
  readonly to: string;
  readonly reason: string;
}

export const FORBIDDEN_EDGES: readonly ForbiddenEdge[] = [
  {
    from: '@security-doctor/core',
    to: '@security-doctor/*',
    reason:
      'The SDK runs in customer production. It may depend on nothing except evidence-schema, ' +
      'which is allow-listed explicitly below.',
  },
  {
    from: '@security-doctor/verification-engine',
    to: '@security-doctor/rules',
    reason:
      'The engine consumes Finding and VerificationPlan (declared in finding-model). Importing ' +
      'rules would let rule code execute inside the verification process.',
  },
  {
    from: '*',
    to: '@security-doctor/cli',
    reason: 'Nothing may import the CLI. It is an orchestrator, not a library.',
  },
];

/** Narrow exceptions to FORBIDDEN_EDGES, each one deliberate. */
export const ALLOWED_EDGES: readonly (readonly [string, string])[] = [
  ['@security-doctor/core', '@security-doctor/evidence-schema'],
];

export interface PackageNode {
  readonly name: string;
  readonly dir: string;
  readonly dependencies: readonly string[];
  readonly peerDependencies: readonly string[];
}

export interface Violation {
  readonly kind: 'cycle' | 'forbidden-edge' | 'zero-dependency';
  readonly message: string;
}

function matches(pattern: string, name: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return name.startsWith(pattern.slice(0, -1));
  return pattern === name;
}

export function findCycles(nodes: readonly PackageNode[]): string[][] {
  const byName = new Map(nodes.map((n) => [n.name, n]));
  const cycles: string[][] = [];
  const state = new Map<string, 'visiting' | 'done'>();

  const visit = (name: string, path: string[]): void => {
    if (state.get(name) === 'done') return;
    if (state.get(name) === 'visiting') {
      cycles.push([...path.slice(path.indexOf(name)), name]);
      return;
    }
    state.set(name, 'visiting');
    for (const dep of byName.get(name)?.dependencies ?? []) {
      if (byName.has(dep)) visit(dep, [...path, name]);
    }
    state.set(name, 'done');
  };

  for (const n of nodes) visit(n.name, []);
  return cycles;
}

export function check(nodes: readonly PackageNode[]): Violation[] {
  const violations: Violation[] = [];

  for (const cycle of findCycles(nodes)) {
    violations.push({ kind: 'cycle', message: `Dependency cycle: ${cycle.join(' -> ')}` });
  }

  for (const node of nodes) {
    if (ZERO_DEPENDENCY_PACKAGES.includes(node.name)) {
      const all = [...node.dependencies, ...node.peerDependencies];
      if (all.length > 0) {
        violations.push({
          kind: 'zero-dependency',
          message:
            `${node.name} must declare zero runtime and peer dependencies, but declares: ${all.join(', ')}. ` +
            'See PRD §10.4 — this constraint is what keeps a supply-chain compromise out of customer production.',
        });
      }
    }

    for (const dep of node.dependencies) {
      if (!dep.startsWith(WORKSPACE_SCOPE)) continue;
      if (ALLOWED_EDGES.some(([f, t]) => f === node.name && t === dep)) continue;
      const edge = FORBIDDEN_EDGES.find((e) => matches(e.from, node.name) && matches(e.to, dep) && node.name !== dep);
      if (edge) {
        violations.push({ kind: 'forbidden-edge', message: `${node.name} -> ${dep} is forbidden. ${edge.reason}` });
      }
    }
  }

  return violations;
}
