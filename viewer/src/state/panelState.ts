/**
 * The panel's state model.
 *
 * This module holds the vocabulary the panel renders and the pure functions
 * that derive it. It holds no data fetching and no rendering, and it invents
 * nothing: every state below is one an API response can actually produce, and
 * a response the model does not recognise produces `unrecognised` rather than
 * an optimistic guess.
 *
 * The three states come from the contract as it stands after WS1's preflight
 * split:
 *
 *   POST /v1/functions/{fn}/executions/preflight -> status: 'needs_review'
 *   POST /v1/executions/{request_id}/send        -> status: 'approved'
 *   any operation                                -> BlockReceipt: 'blocked'
 *
 * Before the split there were two, and a `needs review` chip would have been
 * the UI asserting a privacy state the system never evaluated. That is the one
 * thing this module must not reintroduce, which is why `idle` is a state of its
 * own and why there is no way to construct a state by hand.
 */

/** `PipelineStage` in `contracts/openapi.yaml`, closed and ordered. */
export const PIPELINE_STAGES = [
  'Fields selected',
  'Pseudonymized',
  'Text screened',
  'Payload validated',
  'Policy decision',
  'Model request',
] as const;

export type PipelineStage = (typeof PIPELINE_STAGES)[number];

/**
 * Which component owns which stage, from the `PipelineStage` description in the
 * contract. `J` is the application API itself and owns none: a surface refusal
 * happened before any stage was behind the request, which is why its timeline
 * is empty and must not be drawn as a broken one.
 */
export const STAGE_OWNER: Record<PipelineStage, string> = {
  'Fields selected': 'A — structured payload extractor',
  Pseudonymized: 'C — pseudonymization',
  'Text screened': 'D.1 / D.2 — redaction layers 1 and 2',
  'Payload validated': 'D.3 — redaction layer 3',
  'Policy decision': 'E — policy engine',
  'Model request': 'F — model gateway',
};

export type Layer = 'J' | 'A' | 'D.1' | 'D.2' | 'D.3' | 'E' | 'F' | 'C';

const LAYER_STAGE: Partial<Record<Layer, PipelineStage>> = {
  A: 'Fields selected',
  C: 'Pseudonymized',
  'D.1': 'Text screened',
  'D.2': 'Text screened',
  'D.3': 'Payload validated',
  E: 'Policy decision',
  F: 'Model request',
};

export type PolicyMode = 'strict_local' | 'cloud' | 'authorized_local';

/** The three deployed routes, in the design's own words. Not a control: see
 *  `RouteLabel` below and the note on the `PolicyConfiguration` operation. */
export const ROUTE_LABELS: Record<PolicyMode, string> = {
  strict_local: 'Strict local',
  cloud: 'Cloud',
  authorized_local: 'Authorized local (documented extension, not implemented)',
};

export type RouteState =
  /** `GET /v1/policy` has not been read yet, or could not be read. The panel
   *  says so rather than defaulting to a route the deployment may not be in. */
  | { kind: 'unknown' }
  | { kind: 'policy'; mode: PolicyMode; policyVersion: string; failClosed: boolean };

export type RequestState =
  | { kind: 'idle' }
  | { kind: 'needs_review'; requestId: string; policyVersion: string; stages: PipelineStage[] }
  | { kind: 'approved'; requestId: string; policyVersion: string; stages: PipelineStage[] }
  | {
      kind: 'blocked';
      requestId: string;
      policyVersion: string;
      layer: Layer;
      code: string;
      stages: PipelineStage[];
    }
  | { kind: 'unrecognised'; status: string };

const isStage = (v: unknown): v is PipelineStage =>
  typeof v === 'string' && (PIPELINE_STAGES as readonly string[]).includes(v);

const stagesFrom = (value: unknown): PipelineStage[] =>
  Array.isArray(value) ? value.filter(isStage) : [];

/**
 * Build a state from whatever an operation returned.
 *
 * The one rule: nothing is inferred. A body with a `status` this module does
 * not know becomes `unrecognised`, and the panel says the state was not
 * recognised rather than showing a chip the API never evaluated.
 */
export function stateFromResponse(body: unknown): RequestState {
  // No body at all means no operation ran. That is `idle`, and it is
  // different from a body that arrived and did not say anything recognised.
  if (body === null || body === undefined) return { kind: 'idle' };
  if (typeof body !== 'object') return { kind: 'unrecognised', status: 'response body was not an object' };
  const b = body as Record<string, unknown>;
  const status = typeof b.status === 'string' ? b.status : 'no status field';
  const requestId = typeof b.request_id === 'string' ? b.request_id : 'unknown request';
  const policyVersion = typeof b.policy_version === 'string' ? b.policy_version : 'unknown';
  const stages = stagesFrom(b.stages);

  switch (status) {
    case 'needs_review':
      return { kind: 'needs_review', requestId, policyVersion, stages };
    case 'approved':
      return { kind: 'approved', requestId, policyVersion, stages };
    case 'blocked':
      return {
        kind: 'blocked',
        requestId,
        policyVersion,
        layer: typeof b.layer === 'string' && b.layer in LAYER_STAGE ? (b.layer as Layer) : 'J',
        code: typeof b.code === 'string'
          ? b.code
          : Array.isArray(b.action_codes) && b.action_codes.every((code) => typeof code === 'string')
            ? b.action_codes.join(', ')
            : 'unspecified block code',
        stages,
      };
    default:
      return { kind: 'unrecognised', status };
  }
}

export function routeFromPolicy(body: unknown): RouteState {
  if (typeof body !== 'object' || body === null) return { kind: 'unknown' };
  const p = body as Record<string, unknown>;
  const mode = p.policy_mode;
  if (typeof mode !== 'string' || !(mode in ROUTE_LABELS)) return { kind: 'unknown' };
  return {
    kind: 'policy',
    mode: mode as PolicyMode,
    policyVersion: typeof p.policy_version === 'string' ? p.policy_version : 'unknown',
    failClosed: p.fail_closed !== false,
  };
}

export type StageStatus = 'reached' | 'refused' | 'not-reached' | 'not-applicable';

export type TimelineRow = {
  stage: PipelineStage;
  owner: string;
  status: StageStatus;
  note: string;
};

/**
 * The six-stage timeline, derived from what the server said and nothing more.
 *
 * The contract is explicit that `stages` is a prefix list rather than a
 * per-stage result: it says how far a request got, not what happened at each
 * stage. So a reached stage is labelled "reached" and is not given an invented
 * outcome — a replacement count, a duration, which fields a layer touched.
 * A row whose outcome the contract does not carry says so, in the row.
 */
export function timelineFor(state: RequestState): { rows: TimelineRow[]; emptyReason: string | null } {
  if (state.kind === 'idle' || state.kind === 'unrecognised') {
    return { rows: [], emptyReason: null };
  }
  const stages = state.stages;
  if (stages.length === 0) {
    // The contract calls out exactly one way to get here: layer `J`, a refusal
    // at the request surface, before the pipeline ran. Anything else empty is
    // a shape this panel does not understand, and is reported as such.
    if (state.kind === 'blocked' && state.layer === 'J') {
      return {
        rows: PIPELINE_STAGES.map((stage) => ({
          stage,
          owner: STAGE_OWNER[stage],
          status: 'not-applicable' as StageStatus,
          note: 'Not behind this request: the request surface refused before the pipeline ran.',
        })),
        emptyReason:
          'Refused at the request surface (component J), before the pipeline ran. No stage was ever behind this request.',
      };
    }
    return {
      rows: [],
      emptyReason: 'The response carried no stage list and no surface-refusal layer, so the timeline cannot be drawn.',
    };
  }

  const reached = new Set(stages);
  const refused = state.kind === 'blocked' ? state : null;
  const refusingStage = refused ? LAYER_STAGE[refused.layer] : undefined;
  return {
    rows: PIPELINE_STAGES.map((stage, i) => {
      if (stage === refusingStage) {
        return {
          stage,
          owner: STAGE_OWNER[stage],
          status: 'refused' as StageStatus,
          note: `Refused here. Layer ${refused?.layer ?? 'unknown'}.`,
        };
      }
      if (reached.has(stage)) {
        return {
          stage,
          owner: STAGE_OWNER[stage],
          status: 'reached' as StageStatus,
          note: 'Reached. The contract carries the stage, not its per-stage outcome.',
        };
      }
      const isGateway = i === PIPELINE_STAGES.length - 1;
      return {
        stage,
        owner: STAGE_OWNER[stage],
        status: 'not-reached' as StageStatus,
        note:
          isGateway && state.kind === 'needs_review'
            ? 'Not reached, and not by a block: a preflight stops before the gateway, so no provider was called.'
            : 'Not reached: the request did not get this far.',
      };
    }),
    emptyReason: null,
  };
}

/**
 * What the header chip says. Colour never carries this on its own - each state
 * has a word, and the chip renders the word.
 */
export const STATE_LABEL: Record<RequestState['kind'], string> = {
  idle: 'No request yet',
  needs_review: 'Needs review',
  approved: 'Approved',
  blocked: 'Blocked',
  unrecognised: 'State not recognised',
};

/** A non-colour mark beside the word, so the state survives greyscale. */
export const STATE_MARK: Record<RequestState['kind'], string> = {
  idle: '–',
  needs_review: '●',
  approved: '✓',
  blocked: '✕',
  unrecognised: '?',
};

export type StatusTone = 'neutral' | 'approved' | 'blocked' | 'caution' | 'accent';

export const STATE_TONE: Record<RequestState['kind'], StatusTone> = {
  idle: 'neutral',
  needs_review: 'caution',
  approved: 'approved',
  blocked: 'blocked',
  unrecognised: 'caution',
};

/**
 * The announcement a screen reader hears when the state changes.
 *
 * Every string here is from the closed vocabulary above. A state is announced
 * by its name and its stage names, never by a payload value, a field value or
 * anything a clinician typed: the design requires that validation errors and
 * blocked states be announced without reading sensitive original values aloud.
 */
export function announcementFor(state: RequestState): string {
  switch (state.kind) {
    case 'idle':
      return 'No Medarx request has been made from this panel.';
    case 'needs_review':
      return `Payload validated and awaiting review. Not yet transmitted. Reached ${state.stages.length} of 6 stages.`;
    case 'approved':
      return `Request approved under policy ${state.policyVersion}.`;
    case 'blocked':
      return `Request blocked at layer ${state.layer}. Code ${state.code}. Nothing was transmitted.`;
    case 'unrecognised':
      return `The last response carried an unrecognised status: ${state.status}. The state shown is not one the API produced.`;
  }
}
