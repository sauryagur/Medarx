/**
 * The token build. `design/tokens.json` is the source; this emits the two
 * derived artefacts the rest of the viewer reads:
 *
 *   design/tokens.css  - custom properties, for anything CSS reaches
 *   design/tokens.ts   - a frozen typed object, for the places CSS cannot reach
 *                        (a getComputedStyle probe, a canvas-drawn mark, a test)
 *
 * It also fails the build on the four conditions a token source is allowed to
 * be wrong in. Each has a test of its own firing in the workstream report:
 *
 *   1. a component spec that references a token key that does not exist
 *   2. a token that nothing in viewer/src references and nobody reserved
 *   3. a stale reservation, for a token that has since found a consumer
 *   4. a hand-written hex, rgb() or px literal under viewer/src
 *
 * (4) is the same rule ESLint enforces; it is repeated here so that a file type
 * ESLint does not parse - a .css file, a .html file - is still covered.
 *
 * Run: bun run tokens
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const VIEWER = join(HERE, '..');
const SRC = join(VIEWER, 'src');
const TOKENS_JSON = join(HERE, 'tokens.json');
const CSS_OUT = join(HERE, 'tokens.css');
const TS_OUT = join(HERE, 'tokens.ts');

type Leaf = string | number | { value: string; from: string };
interface Group {
  [key: string]: Node;
}
type Node = Leaf | Group | Node[];


/* ------------------------------------------------------------------ load */

type Source = {
  provenance: Record<string, unknown>;
  colors: Record<string, string>;
  typography: Record<string, Record<string, string | number>>;
  rounded: Record<string, string>;
  spacing: Record<string, string>;
  border: Record<string, Leaf>;
  components: Record<string, Record<string, string>>;
  panel: Record<string, Leaf>;
  reservations: Record<string, string>;
};

const source = JSON.parse(readFileSync(TOKENS_JSON, 'utf8')) as Source;

/* ------------------------------------------------- naming and resolution */

/** `accent-foreground` stays as written; `minHeight` becomes `min-height`, so a
 *  custom property reads like the token path it came from. */
const kebab = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();

/** The other direction: `accent-foreground` -> `accentForeground`. */
const camel = (s: string) => s.replace(/-([a-z0-9])/g, (_, c: string) => c.toUpperCase());

/** The groups the front-matter owns. Anything else must cite a source. */
const FRONT_MATTER_GROUPS = new Set(['colors', 'typography', 'rounded', 'spacing', 'components']);

const errors: string[] = [];

/** Every leaf in the source, keyed by its dotted path
 *  (`colors.accent`, `typography.report.fontSize`, `panel.minWidth`). */
const tokenPaths = new Map<string, string>();

const collect = (path: string, node: Node): void => {
  if (typeof node === 'string' || typeof node === 'number') {
    tokenPaths.set(path, String(node));
    return;
  }
  if (Array.isArray(node)) {
    errors.push(`token ${path} is an array, and no token in the design is`);
    return;
  }
  if (node === null || typeof node !== 'object') {
    errors.push(`token ${path} is ${JSON.stringify(node)}, and a token is a scalar`);
    return;
  }
  if ('value' in node) {
    if (typeof node.value !== 'string') {
      errors.push(`token ${path} has a non-string value`);
      return;
    }
    // A { value, from } leaf is a value the design states in prose. It is
    // only allowed outside the groups transcribed from the front-matter, and
    // only with the sentence it came from.
    if (FRONT_MATTER_GROUPS.has(path.split('.')[0])) {
      errors.push(
        `token ${path} carries a citation, but ${path.split('.')[0]} is transcribed verbatim from the ` +
          `front-matter. A front-matter value is either right or it is a design change; it is not argued for here.`,
      );
    }
    if (typeof node.from !== 'string' || node.from.trim() === '') {
      errors.push(`token ${path} is a { value, from } leaf with no citation for where the value came from`);
    }
    tokenPaths.set(path, node.value);
    return;
  }
  for (const [prop, child] of Object.entries(node as Group)) {
    collect(`${path}.${prop}`, child);
  }
};

for (const [group, value] of Object.entries(source)) {
  if (group === 'provenance' || group === 'reservations') continue;
  for (const [key, node] of Object.entries(value as Group)) {
    collect(`${group}.${key}`, node);
  }
}

/** Resolve `{colors.accent}` against the collected paths. */
const REF = /^\{([a-zA-Z0-9._-]+)\}$/;
const resolve = (raw: string, where: string): string => {
  const m = REF.exec(raw);
  if (!m) return raw;
  const target = m[1];
  const value = tokenPaths.get(target);
  if (value === undefined) {
    errors.push(
      `${where} references {${target}}, which is not a token in tokens.json. ` +
        `A design system that cannot resolve its own component specs is not a token source.`,
    );
    return raw;
  }
  return value;
};

/* ------------------------------------------------------- the variable map */

type Var = { path: string; name: string; value: string };
const vars: Var[] = [];

for (const [path, raw] of tokenPaths) {
  if (path.startsWith('components.')) {
    const [, component, prop] = path.split('.');
    const where = `components.${component}.${prop}`;
    vars.push({ path, name: `--medarx-${component}-${kebab(prop)}`, value: resolve(raw, where) });
    continue;
  }
  if (path.startsWith('typography.')) {
    // A typography leaf is already `typography.<role>.<property>`.
    const parts = path.split('.');
    const role = parts[1];
    const prop = parts[2];
    vars.push({ path, name: `--medarx-type-${role}-${kebab(prop)}`, value: raw });
    continue;
  }
  const [group, key] = path.split('.');
  const prefix =
    group === 'colors' ? 'color' : group === 'rounded' ? 'radius' : group === 'spacing' ? 'spacing' : group;
  vars.push({ path, name: `--medarx-${prefix}-${key}`, value: raw });
}

vars.sort((a, b) => a.name.localeCompare(b.name));

/* --------------------------------------------------- scan what uses them */

const HEX_OR_FUNC =
  /#[0-9a-fA-F]{3,8}\b|\b(?:rgb|rgba|hsl|hsla|hwb|lab|lch|oklch|oklab|color-mix|color)\s*\(/g;
const LENGTH_WITH_UNIT = /\b\d+(?:\.\d+)?(?:px|rem|em|pt|vh|vw|vmin|vmax|ch|ex)\b/g;
const TS_PATH = /\btokens\.[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+\b/g;
// `varRef('colors.accent')` is a reference written in token-path form. It
// reaches the same tokens as the TS module, through a different door, so both
// doors are scanned and either one counts as a use.
const VAR_REF = /\bvarRef\(\s*'([a-zA-Z0-9._-]+)'/g;
const CSS_VAR = /var\(\s*(--medarx-[a-z0-9-]+)/g;

/** The name a token has in the generated TS module, so a `tokens.…` access in
 *  src/ resolves back to the token path it is. */
const TS_INDEX: Record<string, string> = {};
const TS_GROUP: Record<string, string> = { colors: 'color', rounded: 'radius', components: 'component' };
for (const p of tokenPaths.keys()) {
  const segments = p.split('.');
  const group = TS_GROUP[segments[0]] ?? segments[0];
  TS_INDEX[`tokens.${[group, ...segments.slice(1)].map(camel).join('.')}`] = p;
}

const walk = (dir: string, out: string[] = []): string[] => {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
};

const sources = walk(SRC).concat([join(VIEWER, 'index.html')]);
const usedCssVars = new Set<string>();
const usedTokenPaths = new Set<string>();
const unknownTsRefs = new Set<string>();
const literalHits: string[] = [];

/**
 * The code of a file, one entry per line, with block comments removed across
 * line boundaries. A per-line regex is not enough: the continuation lines of a
 * block comment start with `*`, so a naive strip would read a JSDoc paragraph
 * as code and reject a value that only ever existed in prose. A comment that
 * says "do not hard-code #123456" is a comment, not a component.
 */
const codeLines = (text: string): { at: number; code: string; raw: string }[] => {
  const out: { at: number; code: string; raw: string }[] = [];
  let inBlock = false;
  text.split('\n').forEach((raw, i) => {
    let code = '';
    let rest = raw;
    for (;;) {
      if (inBlock) {
        const end = rest.indexOf('*/');
        if (end === -1) return void out.push({ at: i, code, raw });
        rest = rest.slice(end + 2);
        inBlock = false;
        continue;
      }
      const open = rest.indexOf('/*');
      const line = rest.indexOf('//');
      if (line !== -1 && (open === -1 || line < open)) return void out.push({ at: i, code: code + rest.slice(0, line), raw });
      if (open === -1) return void out.push({ at: i, code: code + rest, raw });
      code += rest.slice(0, open);
      rest = rest.slice(open + 2);
      inBlock = true;
    }
  });
  return out;
};

for (const file of sources) {
  const rel = relative(VIEWER, file);
  const text = readFileSync(file, 'utf8');
  for (const { at, code, raw } of codeLines(text)) {
    for (const m of code.matchAll(HEX_OR_FUNC)) {
      literalHits.push(`${rel}:${at + 1}  colour literal  ${m[0]}  -> ${raw.trim()}`);
    }
    for (const m of code.matchAll(LENGTH_WITH_UNIT)) {
      literalHits.push(`${rel}:${at + 1}  length literal ${m[0]}  -> ${raw.trim()}`);
    }
  }
  for (const m of text.matchAll(CSS_VAR)) usedCssVars.add(m[1]);
  for (const m of text.matchAll(VAR_REF)) usedTokenPaths.add(m[1]);
  for (const m of text.matchAll(TS_PATH)) {
    const hit = TS_INDEX[m[0]];
    if (hit) usedTokenPaths.add(hit);
    else unknownTsRefs.add(m[0]);
  }
}

/* ------------------------------------------------------ the four failures */

// 1. unresolved component spec references -> collected in `errors` above.

// 2. and 3. unreferenced / stale-reserved tokens.
const referenced = new Set<string>();
for (const v of vars) {
  if (usedCssVars.has(v.name)) referenced.add(v.path);
}
// A reference may address a leaf or a whole group: `tokens.color` counts every
// colour.
for (const p of usedTokenPaths) {
  for (const t of tokenPaths.keys()) {
    if (t === p || t.startsWith(`${p}.`)) referenced.add(t);
  }
}
for (const u of unknownTsRefs) {
  errors.push(`${u} is read from the token module in src/ but is not a token in tokens.json`);
}

const coversPath = (p: string): boolean => [...tokenPaths.keys()].some((t) => t === p || t.startsWith(`${p}.`));

const unreferenced: string[] = [];
for (const v of vars) {
  if (referenced.has(v.path)) continue;
  if (source.reservations[v.path] || source.reservations[v.path.split('.').slice(0, -1).join('.')]) continue;
  unreferenced.push(`  ${v.path}  ->  ${v.name}`);
}
// A reservation may name a role rather than each of its properties, and it is
// stale the moment anything under it is referenced.
const staleReservations = Object.keys(source.reservations).filter(
  (p) => [...referenced].some((r) => r === p || r.startsWith(`${p}.`)),
);

for (const p of staleReservations) {
  errors.push(
    `reservations.${p} reserves a token that viewer/src now references. ` +
      `A reservation that outlives its reason is a lie about what is still owed; delete it.`,
  );
}
for (const p of Object.keys(source.reservations)) {
  if (!coversPath(p)) {
    errors.push(`reservations.${p} reserves a token path that does not exist in tokens.json`);
  }
  const reason = source.reservations[p];
  if (!reason || !/consumer|WS\d|phase/i.test(reason)) {
    errors.push(`reservations.${p} must name the consumer that will use the token, not just say it is unused`);
  }
}

// 4. hand-written literals under viewer/src.
if (literalHits.length > 0) {
  errors.push(
    `viewer/src contains ${literalHits.length} hand-written value literal(s). ` +
      `Every value a component needs is a token reference:\n    ${literalHits.join('\n    ')}`,
  );
}

if (errors.length > 0) {
  console.error(`\ntoken build FAILED\n`);
  for (const e of errors) console.error(`  ✗ ${e}`);
  console.error('');
  process.exit(1);
}

/* ------------------------------------------------------------- emit CSS */

const cssHeader = `/*
 * GENERATED FILE - do not edit.
 * Source: viewer/design/tokens.json
 * Rebuild: cd viewer && bun run tokens
 *
 * ${vars.length} custom properties. Every one is referenced by viewer/src or
 * reserved with a named consumer; the build fails otherwise.
 */
`;

const cssBody = [
  ':root {',
  ...vars.map((v) => `  ${v.name}: ${v.value};`),
  '}',
  '',
  `/* Focus is a token, not a browser default, so a component cannot lose it by
     forgetting an outline. Design: "strong visible focus", Interaction and
     accessibility. :focus-visible is the whole mechanism: a mouse click does
     not paint a ring, a keyboard press does. */`,
  ':where(a, button, input, select, textarea, [tabindex]):focus-visible {',
  '  outline: 2px solid var(--medarx-color-focus);',
  '  outline-offset: 2px;',
  '  border-radius: var(--medarx-radius-sm);',
  '}',
  '',
  `/* Reduced motion. Design: "reduced-motion behaviour". Every transition and
     animation in the panel is declared here, so one media query removes all of
     them and no component has to consult a preference itself. */`,
  '@media (prefers-reduced-motion: reduce) {',
  '  *,',
  '  *::before,',
  '  *::after {',
  '    transition-duration: 0ms !important;',
  '    animation-duration: 0ms !important;',
  '    animation-iteration-count: 1 !important;',
  '    scroll-behavior: auto !important;',
  '  }',
  '}',
  '',
  `/* Visually hidden, still announced. Emitted here rather than written in a
     component so the pixel dimensions of the clip are not hand-written values
     in src/, where the literal rule would (correctly) reject them. */`,
  '.medarx-sr-only {',
  '  position: absolute;',
  '  width: 1px;',
  '  height: 1px;',
  '  margin: -1px;',
  '  padding: 0;',
  '  overflow: hidden;',
  '  clip-path: inset(50%);',
  '  white-space: nowrap;',
  '  border: 0;',
  '}',
  '',

  `/* Page setup, emitted with the rest so that filling the window needs no
     hand-written length anywhere under src/. */`,
  'html,',
  'body,',
  '#medarx-root {',
  '  height: 100%;',
  '  margin: 0;',
  '}',
  '',
  'body {',
  '  background: var(--medarx-color-canvas);',
  '  color: var(--medarx-color-foreground);',
  '  font-family: var(--medarx-type-body-fontFamily);',
  '}',
].join('\n');


const css = `${cssHeader}${cssBody}`;

/* -------------------------------------------------------------- emit TS */

const indent = (o: unknown, depth: number): string => {
  const pad = '  '.repeat(depth);
  if (typeof o === 'string') return JSON.stringify(o);
  const entries = Object.entries(o as Record<string, unknown>);
  if (entries.length === 0) return '{}';
  return `{\n${entries.map(([k, v]) => `${'  '.repeat(depth + 1)}${JSON.stringify(k)}: ${indent(v, depth + 1)}`).join(',\n')}\n${pad}}`;
};



const colours: Record<string, string> = {};
for (const [path, value] of tokenPaths) if (path.startsWith('colors.')) colours[camel(path.slice(7))] = value;

const typeScale: Record<string, Record<string, string | number>> = {};
for (const role of Object.keys(source.typography)) {
  typeScale[camel(role)] = { ...source.typography[role] };
}

const radii: Record<string, string> = {};
for (const [path, value] of tokenPaths) if (path.startsWith('rounded.')) radii[camel(path.slice(8))] = value;

const spacing: Record<string, string> = {};
for (const [path, value] of tokenPaths) if (path.startsWith('spacing.')) spacing[camel(path.slice(9))] = value;

const panelGeometry: Record<string, string> = {};
for (const [path, value] of tokenPaths) {
  if (!path.startsWith('panel.')) continue;
  const prop = camel(path.slice(6));
  panelGeometry[prop] = path === 'panel.separatorStep' ? resolve(value, path) : value;
}

const componentSpecs: Record<string, Record<string, string>> = {};
for (const [path, value] of tokenPaths) {
  if (!path.startsWith('components.')) continue;
  const [, component, prop] = path.split('.');
  componentSpecs[camel(component)] ??= {};
  componentSpecs[camel(component)][camel(prop)] = resolve(value, path);
}

const cssVarIndex: Record<string, string> = {};
for (const v of vars) cssVarIndex[v.path] = v.name;

const ts = `/*
 * GENERATED FILE - do not edit.
 * Source: viewer/design/tokens.json
 * Rebuild: cd viewer && bun run tokens
 *
 * The same tokens as tokens.css, for the places CSS cannot reach: a
 * getComputedStyle probe, a canvas-drawn diff mark, a Cornerstone overlay
 * label, and the contrast test. Deep-frozen because a token that can be
 * reassigned at runtime is a token with no source.
 */

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const inner of Object.values(value as Record<string, unknown>)) deepFreeze(inner);
  }
  return value;
}

export const tokens = deepFreeze(${indent(
  {
    color: colours,
    type: typeScale,
    radius: radii,
    spacing,
    panel: panelGeometry,
    component: componentSpecs,
  },
  0,
)});

export type Tokens = typeof tokens;

/** Token path -> CSS custom property, for code that needs the var name itself. */
export const cssVar: Readonly<Record<string, string>> = deepFreeze(${indent(cssVarIndex, 0)});

/** A 'var(--medarx-...)' reference for a token path. Throws on an unknown path,
 *  because a silently empty string renders as no styling at all. */
export function varRef(path: string): string {
  const name = cssVar[path];
  if (!name) throw new Error(\`unknown Medarx token: \${path}\`);
  return \`var(\${name})\`;
}
`;

writeFileSync(CSS_OUT, css);
writeFileSync(TS_OUT, ts);

/* --------------------------------------------------------------- report */

const reservedList = Object.keys(source.reservations);
console.log(`tokens: ${tokenPaths.size} leaves -> ${vars.length} css properties, tokens.css, tokens.ts`);
console.log(`tokens: ${referenced.size} referenced by viewer/src, ${reservedList.length} reserved`);
for (const p of reservedList) console.log(`  reserved  ${p}  ${source.reservations[p]}`);
if (unreferenced.length > 0) {
  console.error(`\ntoken build FAILED\n  ✗ ${unreferenced.length} unreferenced token(s):\n${unreferenced.join('\n')}\n`);
  process.exit(1);
}
console.log('tokens: every token is referenced or reserved');
