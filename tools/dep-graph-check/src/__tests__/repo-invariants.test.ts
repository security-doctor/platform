import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Repo-wide invariants that CI must guarantee.
 *
 * These live alongside the dependency-graph checks because both answer the same
 * question — "is this repository still shaped the way we decided?" — and both should
 * fail the build rather than be remembered. Split into its own tool if this grows.
 *
 * The credential checks matter more here than in a normal repo: we are asking people to
 * install our SDK into their production request path (PRD §13.2). A leaked token in our
 * own history would end that conversation permanently.
 */

const ROOT = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));

const SKIP_DIRS = new Set(['node_modules', 'dist', '.turbo', '.git', 'coverage']);

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

// Split so this file never matches its own detector.
const NPM_TOKEN_PATTERN = new RegExp('npm' + '_[A-Za-z0-9]{36}');
const AUTH_LINE_PATTERN = /_authToken|_auth\s*=|_password\s*=/;
const PRIVATE_KEY_PATTERN = /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/;

describe('credential hygiene', () => {
  it('keeps .npmrc free of any credential', () => {
    // .npmrc is deliberately committed: it carries ignore-scripts and provenance
    // settings. In CI, setup-node writes auth into a *runner-local* .npmrc — that copy
    // must never make it back here.
    const npmrc = join(ROOT, '.npmrc');
    expect(existsSync(npmrc)).toBe(true);
    const contents = readFileSync(npmrc, 'utf8');
    expect(AUTH_LINE_PATTERN.test(contents)).toBe(false);
    expect(NPM_TOKEN_PATTERN.test(contents)).toBe(false);
  });

  it('has no untracked .env file sitting in the working tree', () => {
    const stray = readdirSync(ROOT).filter((f) => f.startsWith('.env') && f !== '.env.example');
    expect(stray).toEqual([]);
  });

  it('contains no npm token or private key anywhere in the source tree', () => {
    const offenders: string[] = [];
    for (const file of walk(ROOT)) {
      // Skip our own fixtures and lockfiles; scan text only.
      if (file.endsWith('pnpm-lock.yaml')) continue;
      let text: string;
      try {
        text = readFileSync(file, 'utf8');
      } catch {
        continue; // binary or unreadable
      }
      if (NPM_TOKEN_PATTERN.test(text)) offenders.push(`${relative(ROOT, file)}: npm token`);
      if (PRIVATE_KEY_PATTERN.test(text)) offenders.push(`${relative(ROOT, file)}: private key`);
    }
    expect(offenders).toEqual([]);
  });
});

describe('gitignore covers what it must', () => {
  const required = ['node_modules/', 'dist/', '.env', '*.tgz', '.security/evidence.ndjson'];

  it.each(required)('ignores %s', (pattern) => {
    const contents = readFileSync(join(ROOT, '.gitignore'), 'utf8');
    expect(contents).toContain(pattern);
  });

  it('does NOT ignore the reviewable Security Doctor artifacts (PRD §14.2)', () => {
    // Baselines, suppressions, target attestations and verification results are all
    // meant to be visible in review. Ignoring them is how security debt goes invisible.
    const contents = readFileSync(join(ROOT, '.gitignore'), 'utf8');
    const lines = contents
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('#'));

    for (const artifact of [
      '.security-doctor/baseline.json',
      '.security-doctor/suppressions.yml',
      '.security-doctor/authorization.yml',
      '.security-doctor/verifications/',
    ]) {
      expect(lines).not.toContain(artifact);
    }
  });
});
