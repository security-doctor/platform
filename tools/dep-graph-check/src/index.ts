#!/usr/bin/env tsx
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { check, type PackageNode } from './rules.js';

const ROOT = resolve(process.argv[2] ?? process.cwd());
const WORKSPACE_DIRS = ['packages', 'tools'];

function loadPackages(): PackageNode[] {
  const nodes: PackageNode[] = [];
  for (const group of WORKSPACE_DIRS) {
    const groupDir = join(ROOT, group);
    if (!existsSync(groupDir)) continue;
    for (const name of readdirSync(groupDir)) {
      const manifest = join(groupDir, name, 'package.json');
      if (!existsSync(manifest)) continue;
      const pkg = JSON.parse(readFileSync(manifest, 'utf8')) as Record<string, Record<string, string> | string>;
      nodes.push({
        name: pkg['name'] as string,
        dir: join(group, name),
        dependencies: Object.keys((pkg['dependencies'] as Record<string, string>) ?? {}),
        peerDependencies: Object.keys((pkg['peerDependencies'] as Record<string, string>) ?? {}),
      });
    }
  }
  return nodes;
}

const nodes = loadPackages();
const violations = check(nodes);

if (violations.length === 0) {
  console.log(`dep-graph-check: ${nodes.length} package(s) OK`);
  process.exit(0);
}

console.error(`dep-graph-check: ${violations.length} architectural violation(s)\n`);
for (const v of violations) console.error(`  [${v.kind}] ${v.message}\n`);
process.exit(1);
