/**
 * The three-part function switcher: Draft · Prior Summary · Ask.
 *
 * The phasing table puts Draft in Phase 2 and Prior Summary / Ask in Phase 5.
 * All three are rendered, because the design specifies a three-part switcher
 * and hiding two of them makes the panel look broken rather than scoped. The
 * other two are visible, focusable and disabled, and the panel says in plain
 * words what they will do and that they are not in this version.
 *
 * Three rules this component exists to hold:
 *
 *  1. **Never a tab that accepts input and does nothing.** The two disabled
 *     functions are never activated, so there is no composer behind them and
 *     nothing to type into. Disabled-and-explained is honest;
 *     enabled-and-ignored is a lie.
 *  2. **Never send them.** The API's function enum carries all three and the
 *     pipeline runs over any of them, so a Phase 2 client that let a user
 *     submit `Ask` would get an un-attributed, uncited answer from a 4B model -
 *     exactly what the design forbids. The server has no way to know it is
 *     Phase 2, so the disable here is the only thing standing in the way.
 *  3. **Focusable, not `disabled`.** A native `disabled` button is removed
 *     from the tab order, and a control a keyboard user cannot reach is not
 *     operable by keyboard. These are `aria-disabled` and keep their tab stop,
 *     pointing at the line that explains them.
 */
import { useRef } from 'react';
import type { CSSProperties, KeyboardEvent } from 'react';
import { color, hairline, primaryButton, radius, space, typeStyles } from '../design/tokens';

export type FunctionName = 'Draft' | 'Prior Summary' | 'Ask';

export const FUNCTIONS: readonly FunctionName[] = ['Draft', 'Prior Summary', 'Ask'];

/** Phase 2 ships Draft. The other two are Phase 5 (product spec §14). */
export const AVAILABLE: Record<FunctionName, boolean> = {
  Draft: true,
  'Prior Summary': false,
  Ask: false,
};

export const FUNCTION_NOTE_ID = 'medarx-function-note';

const WHAT_IT_WILL_DO: Record<FunctionName, string> = {
  Draft: 'Draft turns clinician-supplied findings into report text for you to review.',
  'Prior Summary': 'Prior Summary will list the authorized prior reports selected by trusted local records, cite the exact report sections behind each statement, and present them chronologically.',
  Ask: 'Ask will answer questions from authorized report text and metadata, with inline citations that open the source, and an equally prominent abstention when the text does not support an answer.',
};

export function functionAnnouncement(fn: FunctionName): string {
  return `${fn} is not in this version. ${WHAT_IT_WILL_DO[fn]}`;
}

export const tabDomId = (fn: FunctionName) => `medarx-tab-${fn.replace(/\s+/g, '-').toLowerCase()}`;

export function FunctionSwitch({
  active,
  onSelect,
  onRefused,
  onInspect,
}: {
  active: FunctionName;
  onSelect: (fn: FunctionName) => void;
  /** Called when a disabled function is activated, so the panel can announce
   *  why nothing happened instead of leaving the key press with no result. */
  onRefused: (fn: FunctionName) => void;
  /** Called when a disabled function takes focus by keyboard, so a user who
   *  arrows onto it learns what it is before pressing a key that does nothing. */
  onInspect: (fn: FunctionName) => void;
}) {
  // Roving tabindex, as the ARIA tabs pattern requires: the tab list is one
  // tab stop, and the arrow keys move within it. That is what keeps a disabled
  // tab reachable - `tabIndex={-1}` on it is not a removal from the tab order
  // when the arrow keys can still get there, and it would be a removal if they
  // could not. A disabled tab is focusable and announces why; it is not
  // activatable, and there is nothing behind it to type into.
  // Arrows move from the tab that currently has focus, not from the selected
  // one. They have to: a disabled tab can hold focus without being selected,
  // and a pattern that always counted from the selection would pin the user on
  // the first disabled tab and leave the third unreachable.
  const focused = useRef<FunctionName>(active);
  const focusTab = (fn: FunctionName) => {
    focused.current = fn;
    document.getElementById(tabDomId(fn))?.focus();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const i = Math.max(0, FUNCTIONS.indexOf(focused.current));
    const move: Record<string, number> = {
      ArrowRight: 1,
      ArrowLeft: -1,
      Home: -i,
      End: FUNCTIONS.length - 1 - i,
    };
    const delta = move[event.key];
    if (delta === undefined) return;
    event.preventDefault();
    const next = FUNCTIONS[(i + delta + FUNCTIONS.length) % FUNCTIONS.length];
    if (next) focusTab(next);
  };

  return (
    <div
      role="tablist"
      aria-label="Medarx function"
      onKeyDown={onKeyDown}
      style={{ display: 'flex', gap: space.xs, padding: `${space.sm} ${space.md} 0` }}
    >
      {FUNCTIONS.map((fn) => {
        const enabled = AVAILABLE[fn];
        const selected = fn === active;
        return (
          <button
            key={fn}
            role="tab"
            id={tabDomId(fn)}
            aria-selected={selected}
            aria-disabled={enabled ? undefined : true}
            aria-controls="medarx-function-panel"
            aria-describedby={enabled ? undefined : FUNCTION_NOTE_ID}
            tabIndex={selected ? 0 : -1}
            onClick={() => (enabled ? onSelect(fn) : onRefused(fn))}
            onFocus={() => {
              focused.current = fn;
              onInspect(fn);
            }}
            style={tabStyle(selected, enabled)}
          >
            {fn}
          </button>
        );
      })}
    </div>
  );
}

function tabStyle(selected: boolean, enabled: boolean): CSSProperties {
  return {
    ...typeStyles.label,
    flex: '1 1 auto',
    paddingInline: space.sm,
    paddingBlock: space.xs,
    border: `${hairline} solid ${selected ? color.accent : color.border}`,
    borderRadius: radius.sm,
    background: selected ? color.raised : 'transparent',
    minHeight: primaryButton.minHeight,
    cursor: enabled ? 'pointer' : 'not-allowed',
    // The selection is carried by the border and by `aria-selected`, not by
    // the background alone, so it survives greyscale and high-contrast modes.
    textDecoration: selected ? `underline ${hairline}` : 'none',
    textUnderlineOffset: space.xs,
  };
}

/**
 * The standing explanation. It is always present, not shown on demand, because
 * a function that is merely greyed out tells a reader nothing about whether it
 * is broken, deferred, or permanently out of scope.
 */
export function FunctionNote() {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: space.xs,
        padding: `${space.sm} ${space.md} 0`,
      }}
    >
      <p id={FUNCTION_NOTE_ID} style={{ ...typeStyles.body, color: color.muted, margin: 0 }}>
        <strong style={{ color: color.foreground }}>Prior Summary</strong> and <strong style={{ color: color.foreground }}>Ask</strong>{' '}
        are not in this version. They are shown so the switcher is complete, and they are switched
        off rather than quiet, so nothing you type into them goes nowhere.
      </p>
      <ul style={{ ...typeStyles.body, color: color.muted, margin: 0, paddingInlineStart: space.lg }}>
        {FUNCTIONS.filter((fn) => !AVAILABLE[fn]).map((fn) => (
          <li key={fn}>
            <span style={{ color: color.foreground }}>{fn}:</span> {WHAT_IT_WILL_DO[fn]}
          </li>
        ))}
      </ul>
    </div>
  );
}
