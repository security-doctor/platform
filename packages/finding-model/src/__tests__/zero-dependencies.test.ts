import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

/**
 * PRD §10.4: finding-model is a contract package. It must never grow a runtime
 * dependency and must never import another workspace package.
 */
describe('dependency contract', () => {
  const root = fileURLToPath(new URL('../..', import.meta.url));

  it('declares no runtime dependencies', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Record<string, unknown>;
    expect(pkg['dependencies'] ?? {}).toEqual({});
    expect(pkg['peerDependencies'] ?? {}).toEqual({});
  });

  it('imports nothing outside node: builtins and its own source', () => {
    const src = join(root, 'src');
    const offenders: string[] = [];
    for (const file of readdirSync(src).filter((f) => f.endsWith('.ts'))) {
      const text = readFileSync(join(src, file), 'utf8');
      for (const m of text.matchAll(/from '([^']+)'/g)) {
        const spec = m[1]!;
        if (spec.startsWith('./') || spec.startsWith('../') || spec.startsWith('node:')) continue;
        offenders.push(`${file} -> ${spec}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
