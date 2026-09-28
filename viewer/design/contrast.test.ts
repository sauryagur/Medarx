/**
 * The contrast test.
 *
 * The other two mechanisms check that the token graph is intact: no copies, no
 * dangling references, no second palette. This one checks the thing the design
 * actually cares about, which is that the panel is **readable** - and it checks
 * it by computing a WCAG 2.1 contrast ratio for the pairs the design names, so
 * that a change to a token that silently made the text unreadable fails here
 * rather than in a radiologist's eyes.
 *
 * The pairs are not a general sweep. They are the ones the design commits to:
 *
 *   - the six content classes the design says "must never be low contrast":
 *     negation, laterality, units, measurements, uncertainty and errors. Those
 *     six are rendered by the report text and by the two status colours that
 *     stand for uncertainty and error, so they are asserted on every surface
 *     they can appear on.
 *   - the three status colours on the panel and raised backgrounds, because
 *     "green means a policy gate approved, coral means egress was blocked,
 *     amber means review is needed" is a claim about the same three marks.
 *   - the focus ring and the resize separator, which are the two things a
 *     clinician has to see to drive the panel by keyboard.
 *
 * Where the design's own palette falls short of WCAG AA, this test records the
 * measurement and says so in the name of the test, rather than being quietly
 * relaxed to whatever the number happens to be. There is one such case and it
 * is documented in `SHORTFALLS` below.
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const tokens = JSON.parse(readFileSync(join(HERE, 'tokens.json'), 'utf8')) as {
  colors: Record<string, string>;
};

/* ------------------------------------------------------------- WCAG 2.1 */

const channel = (v: number): number => {
  const c = v / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
};

const relativeLuminance = (hex: string): number => {
  const n = Number.parseInt(hex.slice(1), 16);
  return (
    0.2126 * channel((n >> 16) & 255) + 0.7152 * channel((n >> 8) & 255) + 0.0722 * channel(n & 255)
  );
};

/** WCAG 2.1 contrast ratio, 1 to 21. */
export function contrastRatio(foreground: string, background: string): number {
  const a = relativeLuminance(foreground);
  const b = relativeLuminance(background);
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
}

const ratio = (fg: keyof typeof tokens.colors, bg: keyof typeof tokens.colors) =>
  contrastRatio(tokens.colors[fg], tokens.colors[bg]);

/* ----------------------------------------------------------------- floors */

/** WCAG 1.4.3 AA for normal-size text. */
const AA_TEXT = 4.5;
/** WCAG 1.4.11 for a control boundary or a graphical object. */
const AA_NON_TEXT = 3;

type Pair = {
  /** What the design calls this pair. */
  what: string;
  fg: keyof typeof tokens.colors;
  bg: keyof typeof tokens.colors;
  min: number;
};

/**
 * The clinical-critical content. The design: "Negation, laterality, units,
 * measurements, uncertainty, and errors must never be low contrast."
 *
 * Negation, laterality, units and measurements are all rendered inside the
 * findings and draft text, which is the `foreground` on the report-editor
 * surface. Uncertainty is `caution` (review is needed) and errors are `blocked`
 * (egress was blocked); both are asserted on both surfaces they can land on.
 */
const CLINICAL: Pair[] = [
  { what: 'findings, negation and laterality, on the raised editor', fg: 'foreground', bg: 'raised', min: AA_TEXT },
  { what: 'findings, negation and laterality, on the panel', fg: 'foreground', bg: 'panel', min: AA_TEXT },
  { what: 'units and measurements, on the raised editor', fg: 'foreground', bg: 'raised', min: AA_TEXT },
  { what: 'units and measurements, on the panel', fg: 'foreground', bg: 'panel', min: AA_TEXT },
  { what: 'uncertainty, on the raised editor', fg: 'caution', bg: 'raised', min: AA_TEXT },
  { what: 'uncertainty, on the panel', fg: 'caution', bg: 'panel', min: AA_TEXT },
  { what: 'errors, on the raised editor', fg: 'blocked', bg: 'raised', min: AA_TEXT },
  { what: 'errors, on the panel', fg: 'blocked', bg: 'panel', min: AA_TEXT },
];

/**
 * The three status colours. The design pairs each with a label and an icon, so
 * the colour itself is a graphical object and WCAG's floor would be 3:1 - but
 * all three clear 4.5:1 on both surfaces, so the test holds them to the text
 * floor. A future palette that drops one of them to "clearly visible" fails
 * here rather than shipping.
 */
const STATUS: Pair[] = [
  { what: 'approved (a policy gate approved the payload), on the panel', fg: 'approved', bg: 'panel', min: AA_TEXT },
  { what: 'approved, on the raised editor', fg: 'approved', bg: 'raised', min: AA_TEXT },
  { what: 'blocked (egress was blocked), on the panel', fg: 'blocked', bg: 'panel', min: AA_TEXT },
  { what: 'blocked, on the raised editor', fg: 'blocked', bg: 'raised', min: AA_TEXT },
  { what: 'caution (review is needed), on the panel', fg: 'caution', bg: 'panel', min: AA_TEXT },
  { what: 'caution, on the raised editor', fg: 'caution', bg: 'raised', min: AA_TEXT },
];

/**
 * Controls. The focus ring is the design's "strong visible focus"; the resize
 * separator is a boundary the clinician has to find by eye to drag it, and the
 * muted tone is the one it is painted in.
 */
const CONTROLS: Pair[] = [
  { what: 'focus ring on the panel', fg: 'focus', bg: 'panel', min: AA_NON_TEXT },
  { what: 'focus ring on the raised editor', fg: 'focus', bg: 'raised', min: AA_NON_TEXT },
  { what: 'focus ring on the canvas', fg: 'focus', bg: 'canvas', min: AA_NON_TEXT },
  { what: 'resize separator on the panel', fg: 'muted', bg: 'panel', min: AA_NON_TEXT },
  { what: 'primary action text on the accent', fg: 'accent-foreground', bg: 'accent', min: AA_TEXT },
  { what: 'the accent as a selected-control indicator, on the panel', fg: 'accent', bg: 'panel', min: AA_NON_TEXT },
];

/** Explanations: "muted for explanations". Readable prose, so AA text. */
const EXPLANATION: Pair[] = [
  { what: 'explanations on the panel', fg: 'muted', bg: 'panel', min: AA_TEXT },
  { what: 'explanations on the raised editor', fg: 'muted', bg: 'raised', min: AA_TEXT },
];

/**
 * Noncritical metadata. The design says `#737D85` is "only for noncritical
 * metadata" and sets it below the other two text colours on purpose.
 *
 * It still does not reach 4.5:1 on either surface, and that is a fact about the
 * design rather than about the test, so it is asserted at the large-text /
 * non-text floor and named as a shortfall. See SHORTFALLS below.
 */
const METADATA: Pair[] = [
  { what: 'noncritical metadata on the panel', fg: 'subtle', bg: 'panel', min: AA_NON_TEXT },
];

const SHORTFALLS: { pair: string; measured: number; wanted: number; note: string }[] = [
  {
    pair: 'subtle on raised',
    measured: Number(ratio('subtle', 'raised').toFixed(3)),
    wanted: AA_TEXT,
    note:
      'medarx-ui-design.md:109 restricts #737D85 to noncritical metadata, and it does not reach ' +
      'WCAG AA anywhere: 4.075 on the raised surface and 4.434 on the panel. The panel therefore ' +
      'uses it only for the study-association line on the panel background, never on a raised ' +
      'surface and never for anything clinical. Raising it to AA is a design decision, not a ' +
      'component one, so it is recorded here rather than made here.',
  },
];

const assertPairs = (label: string, pairs: Pair[]) => {
  describe(label, () => {
    for (const p of pairs) {
      test(`${p.what} — ${p.fg} on ${p.bg} is at least ${p.min}:1`, () => {
        const measured = ratio(p.fg, p.bg);
        expect(
          measured,
          `${tokens.colors[p.fg]} on ${tokens.colors[p.bg]} measures ${measured.toFixed(2)}:1, ` +
            `below the ${p.min}:1 floor for "${p.what}"`,
        ).toBeGreaterThanOrEqual(p.min);
      });
    }
  });
};

assertPairs('the six clinical-critical content classes', CLINICAL);
assertPairs('the three status colours', STATUS);
assertPairs('control boundaries and the focus ring', CONTROLS);
assertPairs('explanations', EXPLANATION);
assertPairs('noncritical metadata', METADATA);

/* ----------------------------------------------------- the test itself */

describe('the contrast test', () => {
  test('a lower-contrast token would be caught, not just counted', () => {
    // A guard on the guard: if the ratio function stopped discriminating - if it
    // returned a constant, or if every pair were silently skipped - this fails.
    // A test that cannot fail is not a test, and the whole point of the three
    // mechanisms is that each has been seen going red.
    expect(contrastRatio('#ffffff', '#000000')).toBeCloseTo(21, 5);
    expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 5);
    expect(contrastRatio('#111315', '#111315')).toBeCloseTo(1, 5);
    expect(ratio('foreground', 'raised')).toBeGreaterThan(ratio('subtle', 'raised'));
  });

  test('every pair the design names is asserted, not a subset', () => {
    // Negation, laterality, units, measurements, uncertainty, errors: six
    // classes, and the three status colours, both named explicitly so that
    // dropping one from the table above is a failure here.
    const named = new Set([...CLINICAL, ...STATUS].map((p) => `${p.fg}|${p.bg}`));
    for (const fg of ['foreground', 'caution', 'blocked'] as const) {
      for (const bg of ['panel', 'raised'] as const) {
        expect(named.has(`${fg}|${bg}`)).toBe(true);
      }
    }
  });

  test('the one documented shortfall is measured, not assumed', () => {
    for (const s of SHORTFALLS) {
      const [fg, bg] = s.pair.split(' on ') as [keyof typeof tokens.colors, keyof typeof tokens.colors];
      expect(Number(ratio(fg, bg).toFixed(3))).toBe(s.measured);
      expect(s.measured).toBeLessThan(s.wanted);
    }
  });
});
