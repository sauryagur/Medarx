/**
 * The privacy-details drawer: the container and the state model, not the
 * fetching.
 *
 * WS2 builds the box and the vocabulary. A later workstream supplies the
 * audit-record readback that fills it. Nothing here decides a privacy state,
 * derives a payload, or computes a stage: every row comes from what the server
 * said, and the ones the contract does not carry are marked as not carried.
 *
 * Four things it refuses to do, each because the design or the contract says so:
 *
 *  - **It does not claim Medarx's audit record is independent proof.** There is
 *    an `Independent egress capture` section in the design, and it is rendered
 *    only when an external observer artefact is actually present. On a local
 *    route with no external observer it does not render at all - not disabled,
 *    not greyed: absent, because a disabled section reads as "we have it, it is
 *    just not switched on".
 *  - **It does not draw a privacy timeline for a surface refusal.** A `layer` of
 *    `J` means the request surface refused before any stage was behind the
 *    request, so `stages` is empty by construction. That is stated, not drawn
 *    as a missing timeline.
 *  - **It does not invent per-stage outcomes.** `stages` is a prefix list, not a
 *    result per stage; a reached stage says "reached", and the row says the
 *    contract does not carry the outcome.
 *  - **It does not trap focus.** It is a disclosure region, not a modal. The
 *    design traps focus only during the modal privacy review, which is a
 *    different screen, in a different phase.
 */
import type { CSSProperties, ReactNode } from 'react';
import { Badge, Divider, Raised } from '../design/primitives';
import { color, hairline, space, typeStyles } from '../design/tokens';
import type { RequestState, RouteState, TimelineRow } from '../state/panelState';
import { PIPELINE_STAGES, ROUTE_LABELS, STATE_LABEL, timelineFor } from '../state/panelState';
import { PRIVACY_DRAWER_ID } from './PanelHeader';

export type StageStyle = Record<TimelineRow['status'], { color: string; mark: string; label: string }>;

const STAGE_STYLE: StageStyle = {
  reached: { color: color.approved, mark: '✓', label: 'Reached' },
  refused: { color: color.blocked, mark: '✕', label: 'Refused here' },
  'not-reached': { color: color.muted, mark: '–', label: 'Not reached' },
  'not-applicable': { color: color.muted, mark: '–', label: 'Not behind this request' },
};

/**
 * Evidence that something *other than Medarx* observed the outbound bytes.
 *
 * The type has no default and nothing in Phase 2 constructs one, which is the
 * point: the section below renders on the presence of this, so a phase that
 * has no external observer cannot accidentally show a section implying it does.
 */
export type EgressCaptureEvidence = {
  observerKind: 'external';
  origin: string;
  agreesWithApprovedPayload: boolean;
};

function DefinitionRow({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div
      style={{ display: 'flex', flexWrap: 'wrap', gap: space.sm, alignItems: 'baseline' }}
    >
      <dt style={{ ...typeStyles.label, color: color.muted, flex: '0 0 auto' }}>{term}</dt>
      <dd
        style={{
          ...typeStyles.metadata,
          color: color.foreground,
          margin: 0,
          flex: '1 1 0',
          minWidth: 0,
          overflowWrap: 'anywhere',
        }}
      >
        {children}
      </dd>
    </div>
  );
}

function TimelineRowView({ row }: { row: TimelineRow }) {
  const style = STAGE_STYLE[row.status];
  return (
    <li
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1fr) auto',
        gap: space.sm,
        paddingBlock: space.xs,
        alignItems: 'start',
      }}
    >
      <div style={{ minWidth: 0 }}>
        <div style={{ ...typeStyles.body, color: color.foreground }}>{row.stage}</div>
        <div style={{ ...typeStyles.metadata, color: color.muted }}>{row.owner}</div>
        <div style={{ ...typeStyles.metadata, color: color.muted }}>{row.note}</div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: space.xs, whiteSpace: 'nowrap' }}>
        <span aria-hidden="true" style={{ color: style.color }}>
          {style.mark}
        </span>
        <span style={{ ...typeStyles.label, color: color.foreground }}>{style.label}</span>
      </div>
    </li>
  );
}

export function PrivacyDrawer({
  route,
  requestState,
  open,
  functionName,
  egressCapture,
  payloadPreview,
  studyScope,
}: {
  route: RouteState;
  requestState: RequestState;
  open: boolean;
  functionName: string;
  /** Absent until a later workstream reads the preflight response back. The
   *  drawer shows what it is given and says so when it has nothing. */
  egressCapture?: EgressCaptureEvidence;
  payloadPreview?: string;
  studyScope?: string;
}) {
  if (!open) return null;
  const { rows, emptyReason } = timelineFor(requestState);

  return (
    <section
      id={PRIVACY_DRAWER_ID}
      aria-label="Privacy details"
      style={{
        borderTop: `${hairline} solid ${color.border}`,
        padding: space.md,
        // `0 1 auto` rather than `none`: the drawer takes from the panel's
        // height and never more than half of it, so it is one click from the
        // route label and does not consume the viewport by default.
        flexDirection: 'column',
        gap: space.sm,
        background: color.panel,
        // The drawer takes from the panel's height and never more than half of
        // it: the design wants it one click from the route label and not
        // consuming the viewport by default.
        flex: '0 1 auto',
        minHeight: 0,
        maxHeight: '50%',
        overflowY: 'auto',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: space.sm, flexWrap: 'wrap' }}>
        <span style={{ ...typeStyles.label, color: color.muted, flex: '1 1 auto' }}>Privacy details</span>
        <Badge tone="neutral">Route: {route.kind === 'policy' ? ROUTE_LABELS[route.mode] : 'not read'}</Badge>
        <Badge tone="neutral">State: {STATE_LABEL[requestState.kind]}</Badge>
      </div>

      <dl style={{ margin: 0, display: 'flex', flexDirection: 'column', gap: space.xs }}>
        <DefinitionRow term="Function">{functionName}</DefinitionRow>
        <DefinitionRow term="Route">
          {route.kind === 'policy'
            ? `${ROUTE_LABELS[route.mode]} — deployment configuration, read-only`
            : 'Not read from the policy configuration.'}
        </DefinitionRow>
        <DefinitionRow term="Policy version">
          {requestState.kind === 'idle' || requestState.kind === 'unrecognised'
            ? '—'
            : requestState.policyVersion}
        </DefinitionRow>
        <DefinitionRow term="Request id">
          {requestState.kind === 'idle' || requestState.kind === 'unrecognised' ? '—' : requestState.requestId}
        </DefinitionRow>
        <DefinitionRow term="Model">
          {/* The contract does not put `selected_model` on every path: it is
              absent on a refused request, and a drawer that invents one is
              displaying a model that was never chosen. */}
          {requestState.kind === 'blocked' || requestState.kind === 'unrecognised'
            ? 'Not selected — the request did not reach the gateway.'
            : 'Carried on the response, filled in by the workstream that reads it back.'}
        </DefinitionRow>
        <DefinitionRow term="Study scope">{studyScope ?? 'Not correlated by this panel.'}</DefinitionRow>
        <DefinitionRow term="Timestamp">
          Carried on the audit record, which this panel has not read yet.
        </DefinitionRow>
      </dl>

      <Divider />

      <div>
        <div style={{ ...typeStyles.label, color: color.muted, marginBottom: space.xs }}>
          Request timeline — {PIPELINE_STAGES.length} stages
        </div>
        {emptyReason ? (
          <Raised>
            <p style={{ ...typeStyles.body, color: color.foreground, margin: 0 }}>{emptyReason}</p>
          </Raised>
        ) : rows.length === 0 ? (
          <p style={{ ...typeStyles.body, color: color.muted, margin: 0 }}>
            No request has been made from this panel, so there is no timeline to draw.
          </p>
        ) : (
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {rows.map((row) => (
              <TimelineRowView key={row.stage} row={row} />
            ))}
          </ul>
        )}
      </div>

      <Divider />

      <div>
        <div style={{ ...typeStyles.label, color: color.muted, marginBottom: space.xs }}>
          Model-visible payload
        </div>
        {payloadPreview ? (
          <Raised>
            <p style={STYLE_PREVIEW}>{payloadPreview}</p>
            <p style={{ ...typeStyles.metadata, color: color.muted, margin: `${space.sm} 0 0` }}>
              Rendered exactly as the server returned it. The panel never builds this text.
            </p>
          </Raised>
        ) : (
          <p style={{ ...typeStyles.body, color: color.muted, margin: 0 }}>
            No payload preview. It comes from the server's preflight response and is never derived in
            the browser — a client-side redaction is a different algorithm from the server's and will
            disagree with it.
          </p>
        )}
      </div>

      {egressCapture ? (
        <>
          <Divider />
          <div>
            <div style={{ ...typeStyles.label, color: color.muted, marginBottom: space.xs }}>
              Independent egress capture
            </div>
            <p style={{ ...typeStyles.body, color: color.foreground, margin: 0 }}>
              Observed by <strong>{egressCapture.origin}</strong>, a{' '}
              <strong>{egressCapture.observerKind === 'external' ? 'process outside Medarx' : 'Medarx component'}</strong>.
              {egressCapture.agreesWithApprovedPayload
                ? ' The observed bytes agree with the approved payload.'
                : ' The observed bytes do not agree with the approved payload.'}
            </p>
            <p style={{ ...typeStyles.metadata, color: color.muted, margin: `${space.sm} 0 0` }}>
              Medarx's own audit record is not evidence of what left the environment, and is never
              presented as independent proof of it.
            </p>
          </div>
        </>
      ) : null}
    </section>
  );
}

const STYLE_PREVIEW: CSSProperties = {
  ...typeStyles.metadata,
  color: color.foreground,
  margin: 0,
  whiteSpace: 'pre-wrap',
  overflowWrap: 'anywhere',
};

