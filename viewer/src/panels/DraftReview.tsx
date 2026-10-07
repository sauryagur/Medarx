import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import { ApiError, blockReceipt, preflight, readAudit, readPolicy, sendApproved } from '../api/client';
import type { BlockReceipt, ExecutionInput, PolicyResponse, PreflightResponse, StudyContext } from '../api/client';
import { Button, Divider, Raised } from '../design/primitives';
import { color, hairline, radius, space, typeStyles } from '../design/tokens';
import { stateFromResponse } from '../state/panelState';
import type { RequestState } from '../state/panelState';
export type DraftReviewProps = {
  /** Internal synthetic study reference supplied by the host; never derived from DICOM. */
  studyContext?: StudyContext;
  /** Contract-declared synthetic authorization scope supplied by the host. */
  scope?: string;
  /** Same-origin API prefix; defaults to /v1. */
  apiBase?: string;
  /** Optional shell status callback; receives server-derived request states only. */
  onRequestState?: (state: RequestState) => void;
};

type AuditState = 'none' | 'available' | 'missing';

export function DraftReview({ studyContext, scope, apiBase = '/v1', onRequestState }: DraftReviewProps) {
  const [policy, setPolicy] = useState<PolicyResponse | null>(null);
  const [policyError, setPolicyError] = useState('');
  const [source, setSource] = useState('');
  const [preflightResult, setPreflightResult] = useState<PreflightResponse | null>(null);
  const [block, setBlock] = useState<BlockReceipt | null>(null);
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [audit, setAudit] = useState<AuditState>('none');
  const [auditBody, setAuditBody] = useState<unknown>(null);
  const [accepted, setAccepted] = useState(false);

  useEffect(() => {
    let active = true;
    readPolicy(apiBase).then((value) => { if (active) setPolicy(value); })
      .catch(() => { if (active) setPolicyError('Deployment policy could not be read. Draft requests are unavailable.'); });
    return () => { active = false; };
  }, [apiBase]);

  const clearReview = () => {
    setPreflightResult(null); setBlock(null); setDraft(''); setError(''); setAudit('none'); setAuditBody(null); setAccepted(false);
    onRequestState?.({ kind: 'idle' });
  };

  const refreshAudit = async (requestId: string) => {
    if (!scope) return;
    try {
      const record = await readAudit(apiBase, requestId, scope);
      setAuditBody(record); setAudit('available');
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 404) setAudit('missing');
      else setError('Audit readback is unavailable. The request outcome is unchanged.');
    }
  };

  const onPreflight = async () => {
    if (!scope || !studyContext || !source.trim() || !policy) return;
    clearReview(); setBusy(true);
    const input: ExecutionInput = { study_context: studyContext, report_text: source };
    try {
      const result = await preflight(apiBase, scope, input);
      onRequestState?.(stateFromResponse(result));
      setPreflightResult(result); await refreshAudit(result.request_id);
    } catch (cause) {
      const receipt = blockReceipt(cause);
      if (receipt) onRequestState?.(stateFromResponse(receipt));
      if (receipt) { setBlock(receipt); await refreshAudit(receipt.request_id); }
      else setError(cause instanceof ApiError ? cause.message : 'Preflight failed. No send was attempted.');
    } finally { setBusy(false); }
  };

  const onSend = async () => {
    if (!scope || !preflightResult || busy) return;
    setBusy(true); setError('');
    try {
      const result = await sendApproved(apiBase, scope, preflightResult.request_id);
      onRequestState?.(stateFromResponse({ ...result, request_id: preflightResult.request_id, policy_version: preflightResult.policy_version, stages: preflightResult.stages }));
      setDraft(result.draft.content); setAccepted(true); await refreshAudit(preflightResult.request_id);
    } catch (cause) {
      setPreflightResult(null);
      onRequestState?.({ kind: 'idle' });
      if (cause instanceof ApiError && cause.status === 404) {
        setError('This preflight expired or was evicted. Run preflight again before sending.');
      } else setError(cause instanceof ApiError ? cause.message : 'Send failed. No retry was attempted.');
    } finally { setBusy(false); }
  };
 
  const canPreflight = Boolean(scope && studyContext?.study_reference && policy && source.trim() && !busy);
   const auditMissingMessage = block ? 'No audit record was returned for this blocked request.' : accepted ? 'No audit record was returned after send.' : 'No audit record exists yet. A successful preflight alone does not create one.';
  return (
    <section aria-label="Draft workspace" style={ROOT}>
      <h2 className="medarx-sr-only">Draft workspace</h2>
      <div style={ROUTE}><span style={typeStyles.label}>Deployment-fixed route</span><span style={typeStyles.body}>{policy ? policy.policy_mode.replaceAll('_', ' ') + ' · ' + policy.policy_version : policyError || 'Reading deployment policy…'}</span></div>
      {(!scope || !studyContext) && <p role="status" style={SAFE_NOTE}>Draft is unavailable until the host supplies a synthetic study reference and declared request scope. No identifier is inferred from the viewer.</p>}
      <label htmlFor="medarx-report-text" style={typeStyles.label}>Clinician findings</label>
      <textarea id="medarx-report-text" value={source} onChange={(event) => { setSource(event.currentTarget.value); clearReview(); }} rows={5} style={TEXTAREA} aria-describedby="medarx-report-help" />
      <p id="medarx-report-help" style={HELP}>Only this text is sent as report_text after you run preflight. No image or DICOM data is sent.</p>
      <div style={ACTIONS}><Button tone="primary" disabled={!canPreflight} onClick={onPreflight}>{busy ? 'Working…' : 'Review privacy preflight'}</Button><Button tone="secondary" disabled={!preflightResult || accepted || busy} onClick={onSend}>Send approved payload</Button></div>
      {policyError && <p role="alert" style={SAFE_NOTE}>{policyError}</p>}{error && <p role="alert" style={SAFE_NOTE}>{error}</p>}
      {block && <Raised><p style={{ ...typeStyles.label, color: color.blocked, margin: 0 }}>Blocked · {block.layer}</p><p style={typeStyles.body}>Action codes: {block.action_codes.join(', ') || 'none returned'}. No send was attempted.</p><p style={typeStyles.metadata}>Request {block.request_id} · policy {block.policy_version}</p></Raised>}
      {preflightResult && <PreflightSummary result={preflightResult} />}
      {accepted && <p role="status" style={{ ...typeStyles.label, color: color.approved }}>Draft accepted for review</p>}
      {accepted && <div style={COMPARE}><div><label htmlFor="medarx-source" style={typeStyles.label}>Clinician source</label><pre id="medarx-source" style={PANE}>{source}</pre></div><div><label htmlFor="medarx-draft" style={typeStyles.label}>Editable model draft · review required</label><textarea id="medarx-draft" value={draft} onChange={(event) => setDraft(event.currentTarget.value)} rows={10} style={TEXTAREA} /></div><p style={HELP}>Compare source and editable draft side by side. The draft is not clinically validated or submitted.</p></div>}
      {accepted && <DiffView source={source} draft={draft} />}
      {(preflightResult || block) && <section aria-label="Audit readback" style={AUDIT}><Divider /><h3 style={typeStyles.label}>Request audit readback</h3>{audit === 'missing' ? <p style={HELP}>{auditMissingMessage}</p> : audit === 'available' ? <pre style={PANE}>{JSON.stringify(auditBody, null, 2)}</pre> : <p style={HELP}>Reading audit record for this request only…</p>}</section>}
    </section>
  );
}

function PreflightSummary({ result }: { result: PreflightResponse }) {
  return <Raised><h3 style={typeStyles.label}>Server preflight · awaiting your send decision</h3><p style={typeStyles.metadata}>Request {result.request_id} · policy {result.policy_version}</p><p style={typeStyles.metadata}>Approved payload hash: {result.approved_payload_hash}</p><h4 style={typeStyles.label}>Returned payload</h4><pre style={PANE}>{JSON.stringify(result.payload, null, 2)}</pre><h4 style={typeStyles.label}>Field actions</h4><ul style={LIST}>{result.field_actions.map((action, index) => <li key={index}>{action.field}: {action.state}</li>)}</ul><h4 style={typeStyles.label}>Reached preflight stages ({result.stages.length})</h4><ol style={LIST}>{result.stages.map((stage, index) => <li key={index}>{stage}</li>)}</ol></Raised>;
}
function DiffView({ source, draft }: { source: string; draft: string }) {
  const before = source.split('\n');
  const after = draft.split('\n');
  let prefix = 0;
  while (prefix < before.length && prefix < after.length && before[prefix] === after[prefix]) prefix += 1;
  let suffix = 0;
  while (suffix < before.length - prefix && suffix < after.length - prefix && before[before.length - 1 - suffix] === after[after.length - 1 - suffix]) suffix += 1;
  const removed = before.slice(prefix, before.length - suffix).join('\n');
  const added = after.slice(prefix, after.length - suffix).join('\n');
  return <section role="group" aria-label="Accessible draft text diff" style={DIFF}><h3 style={typeStyles.label}>Text diff</h3><p style={HELP}>Unchanged lines are omitted from this restrained comparison. Labels and underlines identify changes without relying on color.</p>{removed && <div style={REMOVED}><strong>Removed from source:</strong><del>{removed}</del></div>}{added && <div style={ADDED}><strong>Added in draft:</strong><ins>{added}</ins></div>}{!removed && !added && <p style={HELP}>No text difference.</p>}</section>;
}

const ROOT: CSSProperties = { display: 'flex', flexDirection: 'column', gap: space.sm, overflowY: 'auto', minHeight: 0, padding: space.sm };
const ROUTE: CSSProperties = { display: 'flex', flexDirection: 'column', gap: space.xs, padding: space.sm, border: hairline + ' solid ' + color.border, borderRadius: radius.md };
const TEXTAREA: CSSProperties = { ...typeStyles.report, color: color.foreground, background: color.raised, border: hairline + ' solid ' + color.border, borderRadius: radius.md, padding: space.sm, width: '100%', boxSizing: 'border-box', resize: 'vertical' };
const HELP: CSSProperties = { ...typeStyles.metadata, color: color.muted, margin: 0 };
const SAFE_NOTE: CSSProperties = { ...typeStyles.body, color: color.caution, margin: 0 };
const ACTIONS: CSSProperties = { display: 'flex', flexWrap: 'wrap', gap: space.sm };
const COMPARE: CSSProperties = { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: space.sm };
const PANE: CSSProperties = { ...typeStyles.report, color: color.foreground, background: color.canvas, border: hairline + ' solid ' + color.border, borderRadius: radius.md, padding: space.sm, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: 0, overflow: 'auto' };
const LIST: CSSProperties = { ...typeStyles.metadata, color: color.foreground, margin: 0, paddingInlineStart: space.lg };
const AUDIT: CSSProperties = { display: 'flex', flexDirection: 'column', gap: space.xs };
const DIFF: CSSProperties = { display: 'flex', flexDirection: 'column', gap: space.xs, padding: space.sm, border: hairline + ' solid ' + color.border, borderRadius: radius.md };
const REMOVED: CSSProperties = { display: 'flex', flexDirection: 'column', gap: space.xs, borderInlineStart: hairline + ' solid ' + color.blocked, paddingInlineStart: space.sm, ...typeStyles.report, color: color.foreground, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' };
const ADDED: CSSProperties = { display: 'flex', flexDirection: 'column', gap: space.xs, borderInlineStart: hairline + ' solid ' + color.approved, paddingInlineStart: space.sm, ...typeStyles.report, color: color.foreground, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', textDecoration: 'underline' };
