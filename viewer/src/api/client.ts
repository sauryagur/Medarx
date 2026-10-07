export type StudyContext = { study_reference: string; modality?: string };
export type ExecutionInput = { study_context: StudyContext; report_text: string };
export type PolicyResponse = { policy_mode: string; policy_version: string };
export type FieldAction = { field: string; state: 'included' | 'transformed' | 'excluded' };
export type PreflightResponse = {
  status: 'needs_review'; request_id: string; policy_version: string; payload: unknown;
  field_actions: FieldAction[]; approved_payload_hash: string; stages: string[];
};
export type BlockReceipt = { status: 'blocked'; request_id: string; layer: string; action_codes: string[]; policy_version: string };
export type SendResponse = { status: 'approved'; draft: { content: string; model_id?: string; finish_reason?: string } };
export type AuditResponse = Record<string, unknown>;

const NOT_FOUND = 'The requested Medarx resource was not found.';
const SAFE_FAILURE = 'The request could not be completed. Review the input and try a new preflight.';

export class ApiError extends Error {
  constructor(readonly status: number, message: string) { super(message); this.name = 'ApiError'; }
}

function endpoint(base: string, path: string): string {
  if (base.replace(/\/$/, '') !== '/v1') throw new Error('API path must use the same-origin /v1 endpoint.');
  return base.replace(/\/$/, '') + path;
}

async function request<T>(base: string, path: string, init: RequestInit = {}, scope?: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(endpoint(base, path), {
      ...init,
      headers: { ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...(scope ? { 'X-Scope': scope } : {}) },
      cache: 'no-store',
    });
  } catch {
    throw new ApiError(0, 'Medarx is unavailable. No request was retried.');
  }
  if (!response.ok) {
    if (response.status === 404) throw new ApiError(404, NOT_FOUND);
    if (response.status === 422) {
      const body: unknown = await response.json().catch(() => null);
      if (body && typeof body === 'object' && 'status' in body && body.status === 'blocked' && 'layer' in body && typeof body.layer === 'string' && 'action_codes' in body && Array.isArray(body.action_codes) && 'request_id' in body && typeof body.request_id === 'string' && 'policy_version' in body && typeof body.policy_version === 'string') {
        throw Object.assign(new ApiError(422, 'Request blocked by privacy policy.'), { receipt: body as BlockReceipt });
      }
    }
    throw new ApiError(response.status, SAFE_FAILURE);
  }
  try { return await response.json() as T; }
  catch { throw new ApiError(response.status, SAFE_FAILURE); }
}

export function readPolicy(base = '/v1'): Promise<PolicyResponse> {
  return request(base, '/policy');
}

export function preflight(base: string, scope: string, input: ExecutionInput): Promise<PreflightResponse> {
  return request(base, '/functions/Draft/executions/preflight', { method: 'POST', body: JSON.stringify(input) }, scope);
}

export function sendApproved(base: string, scope: string, requestId: string): Promise<SendResponse> {
  return request(base, '/executions/' + encodeURIComponent(requestId) + '/send', { method: 'POST' }, scope);
}

export function readAudit(base: string, requestId: string, scope: string): Promise<AuditResponse> {
  return request(base, '/audit/records/' + encodeURIComponent(requestId), {}, scope);
}

export function blockReceipt(error: unknown): BlockReceipt | null {
  if (typeof error !== 'object' || error === null || !('receipt' in error)) return null;
  const receipt = error.receipt;
  if (!receipt || typeof receipt !== 'object') return null;
  return receipt as BlockReceipt;
}
