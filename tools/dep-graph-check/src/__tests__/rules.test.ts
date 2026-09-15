import { describe, it, expect } from 'vitest';
import { check, findCycles, type PackageNode } from '../rules.js';

const node = (name: string, dependencies: string[] = [], peerDependencies: string[] = []): PackageNode =>
  ({ name, dir: `packages/${name.split('/')[1]}`, dependencies, peerDependencies });

describe('architectural rules', () => {
  it('passes a legal graph', () => {
    const graph = [
      node('@security-doctor/evidence-schema'),
      node('@security-doctor/finding-model'),
      node('@security-doctor/core'),
      node('@security-doctor/surface-map', ['@security-doctor/finding-model']),
      node('@security-doctor/rules', ['@security-doctor/finding-model', '@security-doctor/surface-map']),
      node('@security-doctor/verification-engine', ['@security-doctor/finding-model', '@security-doctor/evidence-schema']),
      node('@security-doctor/cli', ['@security-doctor/rules', '@security-doctor/verification-engine']),
    ];
    expect(check(graph)).toEqual([]);
  });

  it('detects a cycle', () => {
    const graph = [
      node('@security-doctor/a', ['@security-doctor/b']),
      node('@security-doctor/b', ['@security-doctor/a']),
    ];
    expect(findCycles(graph).length).toBeGreaterThan(0);
    expect(check(graph).some((v) => v.kind === 'cycle')).toBe(true);
  });

  it('rejects a runtime dependency on a contract package', () => {
    const graph = [node('@security-doctor/finding-model', ['zod'])];
    const v = check(graph);
    expect(v[0]?.kind).toBe('zero-dependency');
    expect(v[0]?.message).toMatch(/customer production/);
  });

  it('rejects a peer dependency on a contract package', () => {
    const graph = [node('@security-doctor/core', [], ['next'])];
    expect(check(graph).some((v) => v.kind === 'zero-dependency')).toBe(true);
  });

  it('rejects security-core importing a workspace package', () => {
    const graph = [
      node('@security-doctor/core', ['@security-doctor/finding-model']),
      node('@security-doctor/finding-model'),
    ];
    // Caught by the zero-dependency rule first, and by the forbidden edge.
    expect(check(graph).length).toBeGreaterThan(0);
  });

  it('rejects verification-engine importing rules', () => {
    const graph = [
      node('@security-doctor/verification-engine', ['@security-doctor/rules']),
      node('@security-doctor/rules'),
    ];
    const v = check(graph).filter((x) => x.kind === 'forbidden-edge');
    expect(v[0]?.message).toMatch(/rule code execute/);
  });

  it('rejects anything importing the CLI', () => {
    const graph = [
      node('@security-doctor/rules', ['@security-doctor/cli']),
      node('@security-doctor/cli'),
    ];
    const v = check(graph).filter((x) => x.kind === 'forbidden-edge');
    expect(v[0]?.message).toMatch(/orchestrator, not a library/);
  });
});

describe('the real workspace', () => {
  it('has no violations', async () => {
    const { readFileSync, readdirSync, existsSync } = await import('node:fs');
    const { join, resolve } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const root = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));
    const nodes: PackageNode[] = [];
    for (const group of ['packages', 'tools']) {
      const dir = join(root, group);
      if (!existsSync(dir)) continue;
      for (const name of readdirSync(dir)) {
        const manifest = join(dir, name, 'package.json');
        if (!existsSync(manifest)) continue;
        const pkg = JSON.parse(readFileSync(manifest, 'utf8'));
        nodes.push({
          name: pkg.name,
          dir: join(group, name),
          dependencies: Object.keys(pkg.dependencies ?? {}),
          peerDependencies: Object.keys(pkg.peerDependencies ?? {}),
        });
      }
    }
    expect(nodes.length).toBeGreaterThan(0);
    expect(check(nodes)).toEqual([]);
  });
});
