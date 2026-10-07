import { afterAll, beforeAll, expect, test } from 'bun:test';
import { createServer, type Server } from 'node:http';
import { blockReceipt, preflight, sendApproved, readAudit, readPolicy } from './client';

let server: Server;
let serverOrigin = '';
const baseUrl = '/v1';
const nativeFetch = globalThis.fetch;
const observed: Array<{ method: string; url: string; body: string; scope?: string }> = [];

beforeAll(async () => {
  server = createServer((request, response) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => (body += chunk));
    request.on('end', () => {
      observed.push({ method: request.method ?? '', url: request.url ?? '', body, scope: request.headers['x-scope'] as string | undefined });
      response.setHeader('content-type', 'application/json');
      if (request.url === '/v1/policy') response.end(JSON.stringify({ policy_mode: 'strict_local', policy_version: 'v1' }));
      else if (request.url === '/v1/functions/Draft/executions/preflight' && body.includes('BLOCKED')) {
        response.statusCode = 422;
        response.end(JSON.stringify({ status: 'blocked', request_id: 'req-blocked', layer: 'D.2', action_codes: ['NER_ENTITY_UNRESOLVED'], policy_version: 'v1' }));
      } else if (request.url === '/v1/functions/Draft/executions/preflight') response.end(JSON.stringify({ status: 'needs_review', request_id: 'req-1', policy_version: 'p1', payload: { report_text: 'safe' }, field_actions: [{ field: 'report_text', state: 'transformed' }], approved_payload_hash: 'sha256:abc', stages: ['Fields selected', 'Pseudonymized', 'Text screened', 'Payload validated', 'Policy decision'] }));
      else if (request.url === '/v1/executions/req-1/send') response.end(JSON.stringify({ status: 'approved', draft: { content: 'draft response' } }));
      else { response.statusCode = 404; response.end(JSON.stringify({ detail: 'private server detail' })); }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address && typeof address !== 'string') serverOrigin = 'http://127.0.0.1:' + address.port;
  Object.defineProperty(globalThis, 'fetch', { configurable: true, value: (input: RequestInfo | URL, init?: RequestInit) => nativeFetch(serverOrigin + String(input), init) });
});

afterAll(async () => { Object.defineProperty(globalThis, 'fetch', { configurable: true, value: nativeFetch }); await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); });

test('preflight posts contract input and send posts no body', async () => {
  observed.length = 0;
  const scope = 'scope:study:STUDY-SYN-000041,scope:function:Draft';
  const result = await preflight(baseUrl, scope, { study_context: { study_reference: 'STUDY-SYN-000041' }, report_text: 'Clinician findings' });
  expect(result.stages).toHaveLength(5);
  expect(result.field_actions[0]?.state).toBe('transformed');
  await sendApproved(baseUrl, scope, result.request_id);
  expect(observed.map(({ method, url, body }) => [method, url, body])).toEqual([
    ['POST', '/v1/functions/Draft/executions/preflight', JSON.stringify({ study_context: { study_reference: 'STUDY-SYN-000041' }, report_text: 'Clinician findings' })],
    ['POST', '/v1/executions/req-1/send', ''],
  ]);
  expect(observed.every((entry) => entry.scope === scope)).toBe(true);
});

test('blocked preflight yields safe receipt without attempting a send', async () => {
  observed.length = 0;
  const scope = 'scope:study:STUDY-SYN-000041,scope:function:Draft';
  let error: unknown;
  try { await preflight(baseUrl, scope, { study_context: { study_reference: 'STUDY-SYN-000041' }, report_text: 'BLOCKED synthetic fixture' }); }
  catch (cause) { error = cause; }
  const receipt = blockReceipt(error);
  expect(receipt?.layer).toBe('D.2');
  expect(receipt?.action_codes).toEqual(['NER_ENTITY_UNRESOLVED']);
  expect((error as Error).message).toBe('Request blocked by privacy policy.');
  expect(observed.map(({ method, url }) => [method, url])).toEqual([['POST', '/v1/functions/Draft/executions/preflight']]);
});

test('policy uses the read-only schema and audit errors never expose response bodies', async () => {
  observed.length = 0;
  expect((await readPolicy(baseUrl)).policy_mode).toBe('strict_local');
  let error: unknown;
  try { await readAudit(baseUrl, 'req-1', 'scope:study:STUDY-SYN-000041,scope:function:Draft'); }
  catch (cause) { error = cause; }
  expect((error as Error).message).toBe('The requested Medarx resource was not found.');
  expect((error as Error).message).not.toContain('private server detail');
  expect(observed.map(({ method, url }) => [method, url])).toEqual([
    ['GET', '/v1/policy'],
    ['GET', '/v1/audit/records/req-1'],
  ]);
});
