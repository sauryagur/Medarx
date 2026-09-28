/**
 * The header's last-request-state chip.
 *
 * Three rules, all from the design's visual language and states sections:
 *
 *  - colour never carries the state alone. The chip renders a word and a mark;
 *    the colour is the third signal, not the first.
 *  - the three status colours mean gate outcomes and nothing else. This chip
 *    never reuses them for severity, progress or emphasis.
 *  - `unrecognised` is a real state, not a hidden failure. If a response
 *    arrives with a status this panel does not know, the chip says so rather
 *    than falling back to a neighbour that looks reassuring.
 */
import type { RequestState, StatusTone } from '../state/panelState';
import { STATE_LABEL, STATE_MARK, STATE_TONE } from '../state/panelState';
import { color, hairline, radius, space, typeStyles } from '../design/tokens';

const TONE_COLOR: Record<StatusTone, string> = {
  neutral: color.muted,
  approved: color.approved,
  blocked: color.blocked,
  caution: color.caution,
  accent: color.accent,
};

export function StateChip({ state }: { state: RequestState }) {
  const tone = STATE_TONE[state.kind];
  return (
    <span
      data-state={state.kind}
      data-tone={tone}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: space.xs,
        ...typeStyles.label,
        color: color.foreground,
        background: color.raised,
        border: `${hairline} solid ${color.border}`,
        borderRadius: radius.sm,
        paddingInline: space.sm,
        paddingBlock: space.xs,
        whiteSpace: 'nowrap',
      }}
    >
      <span aria-hidden="true" style={{ color: TONE_COLOR[tone], fontFamily: typeStyles.body.fontFamily }}>
        {STATE_MARK[state.kind]}
      </span>
      {STATE_LABEL[state.kind]}
    </span>
  );
}
