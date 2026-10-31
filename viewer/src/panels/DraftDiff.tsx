import type { CSSProperties } from 'react';
import * as React from 'react';
import { VisuallyHidden } from '../design/primitives';
import { color, hairline, radius, space, typeStyles } from '../design/tokens';

export type DiffSegment = { kind: 'same' | 'added' | 'removed'; text: string };

// Words and whitespace are separate tokens, so an insertion reads as the inserted words.
const tokens = (text: string): string[] => text.match(/\S+|\s+/g) ?? [];

/**
 * Word-level diff of `source` against `draft`. Adjacent segments of one kind are merged.
 * Joining the non-added segments gives `source` back exactly; joining the non-removed gives `draft`.
 * shortcut: LCS table over the tokens left after trimming the common prefix and suffix, O(n·m) memory; upgrade to a linear-space diff if a findings text grows past a few thousand words.
 */
export function diffWords(source: string, draft: string): DiffSegment[] {
  const before = tokens(source);
  const after = tokens(draft);
  let head = 0;
  while (head < before.length && head < after.length && before[head] === after[head]) head += 1;
  let tailA = before.length;
  let tailB = after.length;
  while (tailA > head && tailB > head && before[tailA - 1] === after[tailB - 1]) {
    tailA -= 1;
    tailB -= 1;
  }
  const a = before.slice(head, tailA);
  const b = after.slice(head, tailB);
  // lcs[i][j] is the length of the common subsequence of a[i..] and b[j..].
  const lcs = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const out: DiffSegment[] = [];
  const push = (kind: DiffSegment['kind'], text: string) => {
    const last = out.at(-1);
    if (last?.kind === kind) last.text += text;
    else out.push({ kind, text });
  };
  before.slice(0, head).forEach((token) => push('same', token));
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      push('same', a[i]!);
      i += 1;
      j += 1;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      push('removed', a[i]!);
      i += 1;
    } else {
      push('added', b[j]!);
      j += 1;
    }
  }
  a.slice(i).forEach((token) => push('removed', token));
  b.slice(j).forEach((token) => push('added', token));
  before.slice(tailA).forEach((token) => push('same', token));
  return out;
}

/** Change is carried by decoration and a text mark, never by colour alone. */
export function DraftDiff({ source, draft }: { source: string; draft: string }) {
  const segments = diffWords(source, draft);
  const changed = segments.some((segment) => segment.kind !== 'same');
  return (
    <section aria-label="Accessible draft text diff" style={FRAME}>
      <h3 style={typeStyles.label}>Text diff</h3>
      <p style={HELP}>Added text is underlined and marked +; removed text is struck through and marked −. Unchanged text is plain.</p>
      {changed ? (
        <div style={TEXT}>
          {segments.map((segment, index) => {
            if (segment.kind === 'same') return <React.Fragment key={index}>{segment.text}</React.Fragment>;
            if (segment.kind === 'added') {
              return (
                <ins key={index} style={ADDED}>
                  <span aria-hidden="true" style={{ color: color.approved }}>+</span>
                  <VisuallyHidden>Added: </VisuallyHidden>
                  {segment.text}
                </ins>
              );
            }
            return (
              <del key={index} style={REMOVED}>
                <span aria-hidden="true" style={{ color: color.blocked }}>−</span>
                <VisuallyHidden>Removed: </VisuallyHidden>
                {segment.text}
              </del>
            );
          })}
        </div>
      ) : (
        <p style={HELP}>No text difference.</p>
      )}
    </section>
  );
}

const FRAME: CSSProperties = { display: 'flex', flexDirection: 'column', gap: space.xs, padding: space.sm, border: hairline + ' solid ' + color.border, borderRadius: radius.md };
const HELP: CSSProperties = { ...typeStyles.metadata, color: color.muted, margin: 0 };
const TEXT: CSSProperties = { ...typeStyles.report, color: color.foreground, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: 0 };
const ADDED: CSSProperties = { textDecoration: 'underline', color: color.foreground };
const REMOVED: CSSProperties = { textDecoration: 'line-through', color: color.foreground };
