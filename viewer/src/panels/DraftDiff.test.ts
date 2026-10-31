import { describe, expect, test } from 'bun:test';
import { diffWords } from './DraftDiff';
import type { DiffSegment } from './DraftDiff';

// Dropping the added text rebuilds the source; dropping the removed text rebuilds the draft.
const side = (segments: DiffSegment[], excluded: 'added' | 'removed') =>
  segments
    .filter((segment) => segment.kind !== excluded)
    .map((segment) => segment.text)
    .join('');

describe('diffWords', () => {
  test('identical text is one unchanged segment', () => {
    expect(diffWords('the lung is clear', 'the lung is clear')).toEqual([{ kind: 'same', text: 'the lung is clear' }]);
  });

  test('an insertion reads as the inserted words only', () => {
    expect(diffWords('the lung is clear', 'the lung is clear today')).toEqual([
      { kind: 'same', text: 'the lung is clear' },
      { kind: 'added', text: ' today' },
    ]);
  });

  test('a deletion reads as the removed words only', () => {
    expect(diffWords('the lung is clear today', 'the lung is clear')).toEqual([
      { kind: 'same', text: 'the lung is clear' },
      { kind: 'removed', text: ' today' },
    ]);
  });

  test('a replaced word is removed and then added', () => {
    expect(diffWords('left lung clear', 'right lung clear')).toEqual([
      { kind: 'removed', text: 'left' },
      { kind: 'added', text: 'right' },
      { kind: 'same', text: ' lung clear' },
    ]);
  });

  test('an empty source is all added and an empty draft is all removed', () => {
    expect(diffWords('', 'abc')).toEqual([{ kind: 'added', text: 'abc' }]);
    expect(diffWords('abc', '')).toEqual([{ kind: 'removed', text: 'abc' }]);
  });

  test('two empty texts have no segments', () => {
    expect(diffWords('', '')).toEqual([]);
  });

  test('each side rebuilds exactly from its segments, with no two neighbours of one kind', () => {
    const source = 'FINDINGS: 7 mm nodule, right upper lobe. Correlate with prior.';
    const draft = 'FINDINGS: 9 mm nodule in the right upper lobe. Correlate with prior study.';
    const segments = diffWords(source, draft);
    expect(side(segments, 'added')).toBe(source);
    expect(side(segments, 'removed')).toBe(draft);
    expect(segments.every((segment, index) => index === 0 || segment.kind !== segments[index - 1]?.kind)).toBe(true);
  });
});
