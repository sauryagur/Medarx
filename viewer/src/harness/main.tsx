/**
 * The harness mount. `bun run dev` opens this.
 *
 * It drives the panel through the states the state model can produce, using
 * fixtures shaped like the contract's responses, so every chip, every timeline
 * row and the surface-refusal case can be seen without a server. The state on
 * screen is always produced by `stateFromResponse` - the harness does not
 * construct a `RequestState` by hand either, so what appears is what the panel
 * would show for that body.
 */
import { StrictMode, useState } from 'react';
import type { CSSProperties } from 'react';
import { createRoot } from 'react-dom/client';
import '../../design/tokens.css';
import { Button, Divider } from '../design/primitives';
import { color, space, typeStyles } from '../design/tokens';
import { MedarxPanel } from '../panels/MedarxPanel';
import { routeFromPolicy, stateFromResponse } from '../state/panelState';
import { ViewerHarness } from './ViewerHarness';

const FIVE_STAGES = [
  'Fields selected',
  'Pseudonymized',
  'Text screened',
  'Payload validated',
  'Policy decision',
];

/** Each fixture is a body shaped like the contract's response for that schema. */
const FIXTURES: { label: string; body: unknown }[] = [
  { label: 'No request yet', body: undefined },
  {
    label: 'Needs review',
    body: { status: 'needs_review', request_id: 'req-0001-a', policy_version: 'v1.2', stages: FIVE_STAGES },
  },
  {
    label: 'Approved',
    body: {
      status: 'approved',
      request_id: 'req-0002-b',
      policy_version: 'v1.2',
      stages: [...FIVE_STAGES, 'Model request'],
    },
  },
  {
    label: 'Blocked at D.2',
    body: {
      status: 'blocked',
      request_id: 'req-0003-c',
      policy_version: 'v1.2',
      layer: 'D.2',
      code: 'NER_ENTITY_UNRESOLVED',
      stages: ['Fields selected', 'Pseudonymized', 'Text screened'],
    },
  },
  {
    label: 'Blocked at J',
    body: { status: 'blocked', request_id: 'req-0004-d', policy_version: 'v1.2', layer: 'J', code: 'FORBIDDEN', stages: [] },
  },
  { label: 'Unrecognised', body: { status: 'queued', request_id: 'req-0005-e' } },
];

const ROUTES: { label: string; body: unknown }[] = [
  { label: 'Route not read', body: undefined },
  {
    label: 'strict_local',
    body: { policy_mode: 'strict_local', policy_version: 'v1.2', implemented_modes: ['strict_local'], fail_closed: true },
  },
  {
    label: 'cloud',
    body: { policy_mode: 'cloud', policy_version: 'v1.2', implemented_modes: ['cloud', 'strict_local'], fail_closed: true },
  },
];

function Picker({ title, items, selected, onSelect }: {
  title: string;
  items: { label: string }[];
  selected: number;
  onSelect: (i: number) => void;
}) {
  return (
    <div style={PICKER_GROUP}>
      <span style={{ ...typeStyles.label, color: color.muted }}>{title}</span>
      <div style={PICKER_ROW}>
        {items.map((item, i) => (
          <Button key={item.label} tone={i === selected ? 'primary' : 'secondary'} onClick={() => onSelect(i)}>
            {item.label}
          </Button>
        ))}
      </div>
    </div>
  );
}

function Harness() {
  const [fixture, setFixture] = useState(0);
  const [routeIndex, setRouteIndex] = useState(1);

  return (
    <ViewerHarness>
      <MedarxPanel
        studyLabel="Study (harness stand-in)"
        route={routeFromPolicy(ROUTES[routeIndex]?.body)}
        requestState={stateFromResponse(FIXTURES[fixture]?.body)}
      >
        <p style={{ ...typeStyles.report, color: color.muted, margin: 0 }}>
          Draft is the only function in this version. The pickers below are harness furniture, not
          part of the panel: they swap in response bodies so every state the model can produce can be
          seen without a server.
        </p>
        <Divider />
        <Picker title="Response fixture" items={FIXTURES} selected={fixture} onSelect={setFixture} />
        <Picker title="Policy configuration" items={ROUTES} selected={routeIndex} onSelect={setRouteIndex} />
      </MedarxPanel>
    </ViewerHarness>
  );
}

const PICKER_GROUP: CSSProperties = { display: 'flex', flexDirection: 'column', gap: space.xs };
const PICKER_ROW: CSSProperties = { display: 'flex', flexWrap: 'wrap', gap: space.xs };

createRoot(document.getElementById('medarx-root') as HTMLElement).render(
  <StrictMode>
    <Harness />
  </StrictMode>,
);
