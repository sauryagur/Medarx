import { expect, test } from 'bun:test';
import { stateFromResponse } from './panelState';
import type { PipelineStage } from './panelState';

const PREFLIGHT_STAGES: PipelineStage[] = [
  'Fields selected',
  'Pseudonymized',
  'Text screened',
  'Payload validated',
  'Policy decision',
];

test('preflight shell state preserves the five server-reported stages', () => {
  expect(stateFromResponse({
    status: 'needs_review',
    request_id: 'req-preflight',
    policy_version: 'policy-1',
    stages: PREFLIGHT_STAGES,
  })).toEqual({
    kind: 'needs_review',
    requestId: 'req-preflight',
    policyVersion: 'policy-1',
    stages: PREFLIGHT_STAGES,
  });
});

test('blocked receipt state preserves all server action codes and empty stages', () => {
  expect(stateFromResponse({
    status: 'blocked',
    request_id: 'req-blocked',
    policy_version: 'policy-1',
    layer: 'D.2',
    action_codes: ['NER_ENTITY_UNRESOLVED', 'LEFTOVER_PATTERN_MATCH'],
  })).toEqual({
    kind: 'blocked',
    requestId: 'req-blocked',
    policyVersion: 'policy-1',
    layer: 'D.2',
    code: 'NER_ENTITY_UNRESOLVED, LEFTOVER_PATTERN_MATCH',
    stages: [],
  });
});
