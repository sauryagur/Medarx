/**
 * The reduced-motion emission test.
 *
 * Design/build.ts owns the mechanism: every transition and animation in the
 * panel is declared once, in its emitted CSS, inside a
 * `@media (prefers-reduced-motion: reduce)` block, so obeying the OS setting is
 * a property of the token build rather than of any one component. This test
 * guards that emission: it must exist, it must zero motion, and it must leave
 * opacity and colour alone (reduced motion disables motion, never perception).
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(HERE, 'tokens.css'), 'utf8');

/** The text of the reduced-motion media query, or '' if the build stopped
 *  emitting it (the whole point of this test). */
const mediaBlock = () => {
  const open = css.indexOf('@media (prefers-reduced-motion: reduce)');
  if (open === -1) return '';
  const body = css.indexOf('{', open);
  const close = css.indexOf('}', body);
  return close === -1 ? css.slice(body + 1) : css.slice(body + 1, close);
};

describe('the reduced-motion emission', () => {
  test('tokens.css declares a prefers-reduced-motion media query', () => {
    expect(css).toContain('@media (prefers-reduced-motion: reduce)');
  });

  test('the media query zeroes transitions and animations', () => {
    const block = mediaBlock();
    expect(block, 'reduced-motion media block missing from emitted CSS').not.toBe('');
    expect(block).toContain('transition-duration: 0ms');
    expect(block).toContain('animation-duration: 0ms');
    expect(block).toContain('animation-iteration-count: 1');
    expect(block).toContain('scroll-behavior: auto');
  });

  test('the media query keeps opacity and colour (disables motion, not perception)', () => {
    const block = mediaBlock();
    expect(block).not.toContain('opacity');
    expect(block).not.toContain('visibility');
    expect(block).not.toContain('color');
  });
});