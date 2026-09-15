import { describe, it, expect } from 'vitest';
import {
  codeFingerprint, dependencyFingerprint, secretFingerprint,
  normalizeSnippet, normalizePath, applyMigrations,
} from '../fingerprint.js';

const SNIPPET = `
  const session = await auth();
  const doc = await db.document.findUnique({ where: { id: params.id } });
  return Response.json(doc);
`;

const base = {
  ruleId: 'SEC-AUTHZ-001',
  path: 'app/api/documents/[id]/route.ts',
  symbol: 'GET',
  snippet: SNIPPET,
};

describe('fingerprint stability', () => {
  it('is unchanged by reformatting and added whitespace', () => {
    const reformatted = SNIPPET.replace(/\n/g, '\n\n').replace(/ {2}/g, '    ');
    expect(codeFingerprint({ ...base, snippet: reformatted })).toBe(codeFingerprint(base));
  });

  it('is unchanged by comments', () => {
    const commented = `// TODO: revisit\n${SNIPPET}\n/* block */`;
    expect(codeFingerprint({ ...base, snippet: commented })).toBe(codeFingerprint(base));
  });

  it('is unchanged by renaming a local variable', () => {
    const renamed = SNIPPET.replace(/\bdoc\b/g, 'document');
    expect(codeFingerprint({ ...base, snippet: renamed })).toBe(codeFingerprint(base));
  });

  it('is unchanged by changing a literal value', () => {
    const a = codeFingerprint({ ...base, snippet: 'const x = "alpha";' });
    const b = codeFingerprint({ ...base, snippet: 'const y = "beta";' });
    expect(a).toBe(b);
  });

  it('never depends on line numbers', () => {
    const shifted = `\n\n\n${SNIPPET}`;
    expect(codeFingerprint({ ...base, snippet: shifted })).toBe(codeFingerprint(base));
  });

  it('survives a file move when a surfaceId is present', () => {
    const withSurface = { ...base, surfaceId: 'next:app:GET /api/documents/[id]' };
    const moved = { ...withSurface, path: 'src/app/api/documents/[id]/route.ts' };
    expect(codeFingerprint(moved)).toBe(codeFingerprint(withSurface));
  });

  it('changes when the ORM method (the sink) changes', () => {
    const changed = SNIPPET.replace('findUnique', 'findFirstOrThrow');
    expect(codeFingerprint({ ...base, snippet: changed })).not.toBe(codeFingerprint(base));
  });

  it('changes when the model being queried changes', () => {
    const changed = SNIPPET.replace('db.document', 'db.invoice');
    expect(codeFingerprint({ ...base, snippet: changed })).not.toBe(codeFingerprint(base));
  });

  it('changes when an ownership check is added', () => {
    const fixed = SNIPPET.replace('{ id: params.id }', '{ id: params.id, ownerId: session.userId }');
    expect(codeFingerprint({ ...base, snippet: fixed })).not.toBe(codeFingerprint(base));
  });

  it('changes when the called function changes', () => {
    const changed = SNIPPET.replace('auth()', 'getSession()');
    expect(codeFingerprint({ ...base, snippet: changed })).not.toBe(codeFingerprint(base));
  });

  it('changes when the rule changes', () => {
    expect(codeFingerprint({ ...base, ruleId: 'SEC-AUTHZ-002' })).not.toBe(codeFingerprint(base));
  });

  it('produces a stable, url-safe, fixed-length id', () => {
    const fp = codeFingerprint(base);
    expect(fp).toMatch(/^[a-z2-7]{26}$/);
    expect(codeFingerprint(base)).toBe(fp);
  });
});

describe('normalisation helpers', () => {
  it('collapses identifiers to positional slots', () => {
    expect(normalizeSnippet('const alpha = beta;')).toBe(normalizeSnippet('const gamma = delta;'));
  });

  it('keeps reserved words that carry meaning', () => {
    expect(normalizeSnippet('await x()')).not.toBe(normalizeSnippet('return x()'));
  });

  it('keeps property names, call callees, object keys and PascalCase references', () => {
    const n = normalizeSnippet('const out = await db.user.findUnique({ where: { id: v } }); return Response.json(out);');
    expect(n).not.toContain('db');      // the client variable is a local: renaming it is safe
    expect(n).toContain('.user');       // the model is preserved
    expect(n).toContain('findUnique');  // the sink is preserved
    expect(n).toContain('where');       // the object key is preserved
    expect(n).toContain('Response');    // the global is preserved
    expect(n).toContain('<id');         // locals are slotted
  });

  it('normalises windows paths', () => {
    expect(normalizePath('app\\api\\route.ts')).toBe('app/api/route.ts');
    expect(normalizePath('./src/index.ts')).toBe('src/index.ts');
  });
});

describe('non-code fingerprints', () => {
  it('ignores the package version so an ineffective bump keeps the finding', () => {
    const a = dependencyFingerprint({ ruleId: 'SEC-DEP-001', packageName: 'lodash', advisoryId: 'GHSA-x', dependencyPath: ['next', 'lodash'] });
    const b = dependencyFingerprint({ ruleId: 'SEC-DEP-001', packageName: 'lodash', advisoryId: 'GHSA-x', dependencyPath: ['next', 'lodash'] });
    expect(a).toBe(b);
  });

  it('distinguishes the same advisory reached by different paths', () => {
    const a = dependencyFingerprint({ ruleId: 'SEC-DEP-001', packageName: 'lodash', advisoryId: 'GHSA-x', dependencyPath: ['next', 'lodash'] });
    const b = dependencyFingerprint({ ruleId: 'SEC-DEP-001', packageName: 'lodash', advisoryId: 'GHSA-x', dependencyPath: ['jest', 'lodash'] });
    expect(a).not.toBe(b);
  });

  it('hashes the secret value rather than embedding it', () => {
    const fp = secretFingerprint({ ruleId: 'SEC-SECRET-001', path: '.env', secretValue: 'sk_live_TOPSECRET' });
    expect(fp).not.toContain('TOPSECRET');
    expect(fp).toMatch(/^[a-z2-7]{26}$/);
  });
});

describe('migrations', () => {
  it('maps an old fingerprint forward so a rule update does not reopen findings', () => {
    expect(applyMigrations('old', { old: 'new' })).toBe('new');
    expect(applyMigrations('untouched', { old: 'new' })).toBe('untouched');
  });
});
