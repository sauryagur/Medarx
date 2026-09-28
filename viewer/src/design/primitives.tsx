/**
 * The primitives WS3/WS5 build on. Every one of them takes its values from
 * `./tokens` - which is token references, not values - so a change to
 * `design/tokens.json` reaches all of them and nothing here has to change.
 *
 * There are exactly two button tones, because the design specifies exactly two
 * button components. Disclosure and icon controls are not buttons in the
 * design's sense and are built as their own components rather than as a third
 * invented tone.
 *
 * Accessibility decisions live here rather than in each call site, so a later
 * workstream gets them by using the primitive:
 *
 *  - `Button` and `Disclosure` are real `<button>`s, so they are in the tab
 *    order, activate on Enter and Space, and carry `aria-expanded` /
 *    `aria-controls` where they are disclosures.
 *  - a disabled control uses `aria-disabled`, not the `disabled` attribute: a
 *    native disabled button is removed from the tab order, and a control a
 *    keyboard user cannot reach is not operable by keyboard.
 *  - a disabled control is marked by its own label and by `aria-disabled`,
 *    never by colour alone, so it may look quieter without carrying the
 *    meaning on its own.
 *  - focus is the `:focus-visible` rule in `design/tokens.css`, so no
 *    component can lose a focus ring by forgetting an `outline`.
 *  - nothing here is modal, so nothing here traps focus. The design traps
 *    focus only during the modal privacy review, which is WS5's.
 */
import type { CSSProperties, ReactNode } from 'react';
import { color, editor, hairline, primaryButton, radius, secondaryButton, space, typeStyles } from './tokens';

export function VisuallyHidden({ children }: { children: ReactNode }) {
  return <span className="medarx-sr-only">{children}</span>;
}

export function Divider({ orientation = 'horizontal' }: { orientation?: 'horizontal' | 'vertical' }) {
  return (
    <div
      role="presentation"
      style={
        orientation === 'horizontal'
          ? { height: hairline, background: color.border, flex: 'none' }
          : { width: hairline, background: color.border, alignSelf: 'stretch', flex: 'none' }
      }
    />
  );
}

export type ButtonTone = 'primary' | 'secondary';

export function Button({
  children,
  onClick,
  tone = 'secondary',
  disabled = false,
  describedBy,
  type = 'button',
  fullWidth = false,
}: {
  children: ReactNode;
  onClick?: () => void;
  tone?: ButtonTone;
  /** Rendered as `aria-disabled` so the control keeps its place in the tab
   *  order and can carry, in `describedBy`, the reason it does nothing. */
  disabled?: boolean;
  describedBy?: string;
  type?: 'button' | 'submit';
  fullWidth?: boolean;
}) {
  return (
    <button
      type={type}
      onClick={disabled ? undefined : onClick}
      aria-disabled={disabled || undefined}
      aria-describedby={describedBy}
      data-tone={tone}
      data-disabled={disabled ? '' : undefined}
      style={{ ...buttonStyle(tone, disabled), width: fullWidth ? '100%' : undefined }}
    >
      {children}
    </button>
  );
}

function buttonStyle(tone: ButtonTone, disabled: boolean): CSSProperties {
  const spec = tone === 'primary' ? primaryButton : secondaryButton;
  const shared: CSSProperties = {
    minHeight: spec.minHeight,
    borderRadius: spec.radius,
    paddingInline: space.md,
    ...typeStyles.label,
    cursor: disabled ? 'not-allowed' : 'pointer',
  };
  if (tone === 'primary') {
    // A disabled primary action stops looking like the action it is not, and
    // reads as the muted variant instead. The label, not the paint, is what
    // says "this will not happen".
    return {
      ...shared,
      background: disabled ? secondaryButton.background : primaryButton.background,
      color: disabled ? color.muted : primaryButton.text,
      border: `${hairline} solid ${disabled ? secondaryButton.border : primaryButton.background}`,
    };
  }
  return {
    ...shared,
    background: secondaryButton.background,
    color: disabled ? color.muted : secondaryButton.text,
    border: `${hairline} solid ${secondaryButton.border}`,
  };
}

/**
 * A disclosure control: transparent, label-coloured, and paired with the region
 * it controls. `aria-expanded` and `aria-controls` are the whole mechanism; the
 * caller supplies the ids and the panel, and the button has no opinion about
 * whether the panel is a modal. It is not one.
 */
export function Disclosure({
  children,
  expanded,
  controls,
  onToggle,
  describedBy,
}: {
  children: ReactNode;
  expanded: boolean;
  controls: string;
  onToggle: () => void;
  describedBy?: string;
}) {
  return (
    <button
      type="button"
      aria-expanded={expanded}
      aria-controls={controls}
      aria-describedby={describedBy}
      onClick={onToggle}
      style={TRANSPARENT_CONTROL}
    >
      {children}
    </button>
  );
}

/** The same transparent treatment for a control that is not a disclosure. */
export const TRANSPARENT_CONTROL: CSSProperties = {
  ...typeStyles.label,
  minHeight: primaryButton.minHeight,
  paddingInline: space.sm,
  paddingBlock: space.xs,
  background: 'transparent',
  color: color.muted,
  border: `${hairline} solid transparent`,
  borderRadius: radius.sm,
  cursor: 'pointer',
};

export function SectionLabel({ children, id }: { children: ReactNode; id?: string }) {
  return (
    <div id={id} style={{ ...typeStyles.label, color: color.muted }}>
      {children}
    </div>
  );
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'accent' }) {
  return (
    <span
      style={{
        ...typeStyles.metadata,
        color: tone === 'accent' ? color.accent : color.muted,
        border: `${hairline} solid ${tone === 'accent' ? color.accent : color.border}`,
        borderRadius: radius.sm,
        paddingInline: space.xs,
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </span>
  );
}

/**
 * A raised surface: the design's report-editor layer, with its radius. WS2 uses
 * it for the explanatory blocks, so the raised surface is exercised by the
 * shell rather than first introduced by whichever workstream writes a composer.
 */
export function Raised({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return (
    <div
      style={{
        background: editor.background,
        color: editor.text,
        borderRadius: editor.radius,
        border: `${hairline} solid ${color.border}`,
        padding: space.md,
        ...style,
      }}
    >
      {children}
    </div>
  );
}
