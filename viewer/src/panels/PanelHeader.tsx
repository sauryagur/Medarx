/**
 * The compact header.
 *
 * It carries five things, per the design's layout section: the product name,
 * the current study association, the active route, the last request state, and
 * the collapse control. It does not carry a route *control*.
 *
 * The route is read-only by construction, not by convention. There is no
 * handler here that could change it, no state and no prop: the header renders
 * what `GET /v1/policy` reported, and the line beside it says so. The design
 * document says "Cloud is selectable" and that sentence is wrong - the contract
 * says the policy mode is a deployment configuration precisely so a caller
 * cannot route around the boundary, and a working selector in the panel would
 * be a second, unaudited way to choose it.
 *
 * Nothing here reads a study identifier. The panel receives a study for
 * scoping and shows a study association; OHIF has `PatientName` and
 * `PatientID` in memory, and a header that echoed either would put PHI in the
 * copilot's DOM, in every screenshot of it and in every export.
 *
 * It is compact because the design says so: a 400px-wide panel cannot afford a
 * header that spends a third of its height on chrome, so the route note is set
 * at label size and the controls sit in one row.
 */
import { Disclosure, TRANSPARENT_CONTROL } from '../design/primitives';
import { StateChip } from './StateChip';
import { color, hairline, space, typeStyles } from '../design/tokens';
import { ROUTE_LABELS } from '../state/panelState';
import type { RequestState, RouteState } from '../state/panelState';

export const ROUTE_NOTE_ID = 'medarx-route-note';
export const PRIVACY_DRAWER_ID = 'medarx-privacy-details';

function RouteBlock({ route }: { route: RouteState }) {
  if (route.kind === 'unknown') return null;
  return (
    <div style={{ minWidth: 0 }}>
      <div
        style={{
          ...typeStyles.body,
          color: color.foreground,
          display: 'flex',
          alignItems: 'baseline',
          gap: space.xs,
          flexWrap: 'wrap',
        }}
      >
        <span style={typeStyles.label} id="medarx-route-label">
          Route
        </span>
        <span data-testid="medarx-route" style={{ color: color.foreground }}>
          {route.kind === 'policy' ? ROUTE_LABELS[route.mode] : 'Route not read'}
        </span>
        {route.kind === 'policy' ? (
          <span style={typeStyles.metadata}>
            policy {route.policyVersion} · fail-closed {route.failClosed ? 'on' : 'off'}
          </span>
        ) : null}
      </div>
      <p
        id={ROUTE_NOTE_ID}
        style={{ ...typeStyles.label, color: color.muted, margin: `${space.xs} 0 0`, fontWeight: 400 }}
      >
        {route.kind === 'policy'
          ? 'Read-only: a deployment configuration, not something a request or this panel can choose.'
          : 'Not read from the policy configuration yet, so no route is shown. Nothing here defaults to a route the deployment may not be in.'}
      </p>
    </div>
  );
}

export function PanelHeader({
  studyLabel,
  route,
  requestState,
  drawerOpen,
  onToggleDrawer,
  onToggleCollapsed,
}: {
  studyLabel: string;
  route: RouteState;
  requestState: RequestState;
  drawerOpen: boolean;
  onToggleDrawer: () => void;
  onToggleCollapsed: () => void;
}) {
  return (
    <header
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: space.xs,
        padding: space.md,
        borderBottom: `${hairline} solid ${color.border}`,
        flex: 'none',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: space.sm }}>
        <span style={{ ...typeStyles.heading, color: color.foreground, flex: '1 1 auto' }}>Medarx</span>
        <StateChip state={requestState} />
      </div>

      <div style={{ ...typeStyles.metadata, color: color.muted }}>{studyLabel}</div>

      <RouteBlock route={route} />

      <div style={{ display: 'flex', alignItems: 'center', gap: space.xs, flexWrap: 'wrap' }}>
        <Disclosure expanded={drawerOpen} controls={PRIVACY_DRAWER_ID} onToggle={onToggleDrawer}>
          {drawerOpen ? 'Hide privacy details' : 'Privacy details'}
        </Disclosure>
        <button type="button" onClick={onToggleCollapsed} style={TRANSPARENT_CONTROL}>
          Collapse panel
        </button>
      </div>
    </header>
  );
}
