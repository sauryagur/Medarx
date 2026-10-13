/**
 * Read-only view of `GET /v1/policy` — the panel's route indicator, and
 * nothing else.
 *
 * ## There is no selector here, and there will not be one
 *
 * `GET /v1/policy` says, in the contract's own words, that a client *"must
 * render this value read-only and must not offer a control that changes it"*,
 * and that changing modes *"is a deployment change — a restart with a
 * different configuration — and there is no endpoint, in that document or any
 * other, that performs it"*. So this module can only do a GET. It exports no
 * setter, takes no mode argument, and the only thing it can produce is what
 * the deployment reports about itself.
 *
 * The UI design document's "Cloud is selectable" is being corrected, not
 * implemented: a working selector would be a second, unaudited way to choose
 * the boundary, reaching a different policy than the one every block receipt
 * and audit record was written under.
 *
 * ## Why this lives in `ohif/` and not in `src/api/`
 *
 * `viewer/src/` is the panel and its design system, and it is deliberately
 * independent of both the host viewer and the network. This file is host-side
 * glue: it needs a base URL for the deployment's own API, and it is the only
 * place in the viewer that fetches anything. The workstream that owns the API
 * client (`src/api/client.ts`) will replace this with the real one; until then
 * the panel shows what it can prove and refuses to show what it cannot.
 *
 * ## What it does with a failure
 *
 * A failure is `RouteState { kind: 'unknown' }`, which the panel renders as an
 * unread route. It is never a default route. A panel that opened on "Strict
 * local" because that was the convenient default would be asserting a privacy
 * boundary that nothing in the system evaluated.
 */
import type { RouteState } from '../src/state/panelState';

/** The contract's enum, closed. An unrecognised value is not a route. */
const POLICY_MODES = ['strict_local', 'cloud', 'authorized_local'] as const;

export const MEDARX_API_BASE =
  (typeof window !== 'undefined' && window.MEDARX_API_BASE) || 'http://127.0.0.1:8000';

export type PolicySnapshot = {
  policyMode: string;
  policyVersion: string;
  failClosed: boolean;
};

function toRouteState(body: unknown): RouteState {
  if (typeof body !== 'object' || body === null) {
    return { kind: 'unknown' };
  }
  const { policy_mode: mode, policy_version: version, fail_closed: failClosed } = body as Record<
    string,
    unknown
  >;
  if (typeof mode !== 'string' || !POLICY_MODES.includes(mode as (typeof POLICY_MODES)[number])) {
    return { kind: 'unknown' };
  }
  if (typeof version !== 'string' || version.length === 0) {
    return { kind: 'unknown' };
  }
  return {
    kind: 'policy',
    mode: mode as (typeof POLICY_MODES)[number],
    policyVersion: version,
    // The contract pins this to `const: true`. A response that says otherwise
    // is not the contract's response, so the indicator refuses to render it.
    failClosed: failClosed === true,
  };
}

/** One GET. No body, no headers, no scope: the operation declares no `403`. */
export async function readPolicyRoute(
  baseUrl: string = MEDARX_API_BASE,
  signal?: AbortSignal,
): Promise<RouteState> {
  try {
    const response = await fetch(`${baseUrl.replace(/\/$/, '')}/v1/policy`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal,
    });
    if (!response.ok) {
      return { kind: 'unknown' };
    }
    return toRouteState(await response.json());
  } catch {
    // Network error, CORS, abort, malformed JSON: all of them mean the route
    // is not known, and all of them are the same answer.
    return { kind: 'unknown' };
  }
}
