import { createHash } from 'node:crypto';

/**
 * Structural fingerprinting — PRD §8.5.
 *
 * A finding must keep its identity when the file is reformatted, lines shift, a local
 * variable is renamed, or the file moves; and must lose it when the code changes
 * meaningfully. Line numbers are therefore NEVER an input — putting them in is the most
 * common mistake in this class of tool and it makes baselines useless.
 */

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

function base32(bytes: Uint8Array, chars: number): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    if (out.length >= chars) break;
  }
  return out.slice(0, chars);
}

function hash(parts: readonly string[], chars = 26): string {
  const h = createHash('sha256').update(parts.join('\u0000'), 'utf8').digest();
  return base32(h, chars);
}

/**
 * AST-shaped normalisation without a parser.
 *
 * Strips comments, collapses whitespace, replaces string/number literals with type tokens,
 * and replaces *local* identifiers with positional slots so renaming a variable does not
 * change the fingerprint.
 *
 * Crucially it does NOT anonymise property names, call callees, object keys, or
 * PascalCase references. Those are semantically load-bearing: `db.user.findUnique` and
 * `db.user.findFirstOrThrow` are different sinks, and a fingerprint that cannot tell them
 * apart cannot tell you the code changed. An earlier version slotted everything and
 * silently collapsed those two — the property tests below catch exactly that.
 *
 * This is the fallback for pattern and engine-backed findings. Type-aware rules have a
 * real AST and should pass a canonical printed form instead.
 */
export function normalizeSnippet(snippet: string): string {
  const withoutNoise = snippet
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1 ')
    .replace(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g, '<str>')
    .replace(/\b\d+(?:\.\d+)?\b/g, '<num>');

  const slots = new Map<string, string>();
  const identifier = /[A-Za-z_$][A-Za-z0-9_$]*/g;

  const out = withoutNoise.replace(identifier, (word, offset: number) => {
    if (RESERVED.has(word)) return word;

    // A property or method name: `db.document`, `.findUnique`
    const before = withoutNoise.slice(Math.max(0, offset - 32), offset);
    if (/[.?]\s*$/.test(before)) return word;

    // A type, class or global: Response, Prisma, URL
    if (/^[A-Z]/.test(word)) return word;

    const after = withoutNoise.slice(offset + word.length, offset + word.length + 8);
    // A call callee: `auth()`, `findUnique(`
    if (/^\s*\(/.test(after)) return word;
    // An object key or label: `{ where: ... }`
    if (/^\s*:/.test(after)) return word;

    let slot = slots.get(word);
    if (slot === undefined) {
      slot = `<id${slots.size}>`;
      slots.set(word, slot);
    }
    return slot;
  });

  return out.replace(/\s+/g, ' ').trim();
}

/** Kept verbatim because they carry meaning: changing them changes the code's behaviour. */
const RESERVED = new Set([
  'await', 'async', 'return', 'if', 'else', 'for', 'while', 'const', 'let', 'var',
  'function', 'class', 'new', 'throw', 'try', 'catch', 'finally', 'typeof', 'instanceof',
  'true', 'false', 'null', 'undefined', 'export', 'import', 'from', 'default', 'this',
]);

/** POSIX separators, no leading "./", lowercase drive letters stripped. */
export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^[A-Za-z]:\//, '/');
}

export interface CodeFingerprintInput {
  readonly ruleId: string;
  /** Preferred over `path` when present: a route that moves files keeps its identity. */
  readonly surfaceId?: string;
  readonly path: string;
  /** Enclosing export/function path, e.g. "GET" or "handlers.updateUser". */
  readonly symbol?: string;
  readonly snippet?: string;
  /** Extra discriminator: cookie name, header name, CWE — whatever makes two hits distinct. */
  readonly discriminator?: string;
}

export function codeFingerprint(input: CodeFingerprintInput): string {
  return hash([
    input.ruleId,
    input.surfaceId ?? normalizePath(input.path),
    input.symbol ?? '',
    input.snippet ? hash([normalizeSnippet(input.snippet)], 16) : '',
    input.discriminator ?? '',
  ]);
}

export interface DependencyFingerprintInput {
  readonly ruleId: string;
  readonly packageName: string;
  readonly advisoryId: string;
  /** Path from a direct dependency, so the same CVE in two places is two findings. */
  readonly dependencyPath: readonly string[];
}

/** Deliberately excludes the version: a bump that does not fix the issue keeps the finding. */
export function dependencyFingerprint(input: DependencyFingerprintInput): string {
  return hash([input.ruleId, input.packageName, input.advisoryId, input.dependencyPath.join('>')]);
}

export interface SecretFingerprintInput {
  readonly ruleId: string;
  readonly path: string;
  readonly symbol?: string;
  /** The raw value is hashed here and never stored anywhere else. */
  readonly secretValue: string;
}

export function secretFingerprint(input: SecretFingerprintInput): string {
  return hash([
    input.ruleId,
    normalizePath(input.path),
    input.symbol ?? '',
    hash([input.secretValue], 16),
  ]);
}

/**
 * Rule releases that change fingerprint inputs must ship a migration entry, or a rule
 * update mass-reopens every finding it touches. CI asserts this map covers any rule
 * whose fingerprint version changed (PRD §8.5).
 */
export type FingerprintMigration = Readonly<Record<string, string>>;

export function applyMigrations(fingerprint: string, migrations: FingerprintMigration): string {
  return migrations[fingerprint] ?? fingerprint;
}
