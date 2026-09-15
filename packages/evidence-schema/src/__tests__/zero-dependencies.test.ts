import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * PRD §10.4: evidence-schema is a contract package and must never grow a
 * runtime dependency. Enforced here so the constraint cannot rot silently.
 */
describe('dependency contract', () => {
  it('declares no runtime dependencies', () => {
    const pkgPath = fileURLToPath(new URL('../../package.json', import.meta.url));
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
    expect(pkg['dependencies'] ?? {}).toEqual({});
    expect(pkg['peerDependencies'] ?? {}).toEqual({});
  });
});
