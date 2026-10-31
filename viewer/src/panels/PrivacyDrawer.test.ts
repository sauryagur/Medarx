import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { PreflightResponse } from '../api/client';
import { maskValue, payloadPreviewView, PrivacyDrawer } from './PrivacyDrawer';

const preflight: PreflightResponse = {
  status: 'needs_review',
  request_id: 'req-1',
  policy_version: 'p1',
  payload: {
    function: 'Draft',
    report_text: 'Nodule SYN-0041 seen',
    dicom_fields: { modality: 'CT', study_date: '20240101' },
    study_ref: 'STUDY-SYN-000041',
    policy_version: 'p1',
    payload_hash: 'sha256:payload',
    input_hash: 'sha256:input',
  },
  field_actions: [
    { field: 'report_text', state: 'transformed' },
    { field: 'dicom_metadata.PatientID', state: 'excluded' },
    { field: 'dicom_fields.modality', state: 'included' },
  ],
  approved_payload_hash: 'sha256:approved',
  stages: ['Fields selected'],
};

describe('maskValue', () => {
  test('hides letters and digits and keeps the shape', () => {
    expect(maskValue('SYN-0041')).toBe('•••-••••');
  });
});

describe('payloadPreviewView', () => {
  test('no preflight means no preview, so the caller keeps its placeholder', () => {
    expect(payloadPreviewView(undefined)).toBeNull();
  });

  test('groups field actions by state and masks every payload value', () => {
    const view = payloadPreviewView(preflight);
    expect(view?.categories).toEqual([
      { state: 'included', fields: ['dicom_fields.modality'] },
      { state: 'transformed', fields: ['report_text'] },
      { state: 'excluded', fields: ['dicom_metadata.PatientID'] },
    ]);
    expect(view?.hashes).toEqual([
      { term: 'Approved payload hash', value: 'sha256:approved' },
      { term: 'Payload hash', value: 'sha256:payload' },
      { term: 'Input hash', value: 'sha256:input' },
    ]);
    expect(view?.maskedValues).toEqual([
      { field: 'report_text', masked: '•••••• •••-•••• ••••' },
      { field: 'study_ref', masked: '•••••-•••-••••••' },
      { field: 'dicom_fields.modality', masked: '••' },
      { field: 'dicom_fields.study_date', masked: '••••••••' },
    ]);
  });

  test('drops any payload member the contract does not name, such as a mapping store', () => {
    const extra = { ...preflight.payload, mapping_store: { 'SYN-0041': 'Nodule' } };
    const view = payloadPreviewView({ ...preflight, payload: extra });
    expect(JSON.stringify(view)).not.toContain('mapping_store');
    expect(JSON.stringify(view)).not.toContain('Nodule');
  });

  test('omits the optional hashes the server did not send', () => {
    const payload = { ...preflight.payload, payload_hash: undefined, input_hash: undefined };
    expect(payloadPreviewView({ ...preflight, payload })?.hashes).toEqual([
      { term: 'Approved payload hash', value: 'sha256:approved' },
    ]);
  });
});

describe('PrivacyDrawer', () => {
  const props = { route: { kind: 'unknown' as const }, requestState: { kind: 'idle' as const }, open: true, functionName: 'Draft' };

  test('omits the egress section when no external observer evidence is given', () => {
    expect(renderToStaticMarkup(React.createElement(PrivacyDrawer, props))).not.toContain('Independent egress capture');
  });

  test('renders the egress section when external observer evidence is given', () => {
    const egressCapture = { observerKind: 'external' as const, origin: 'egress proxy', agreesWithApprovedPayload: true };
    expect(renderToStaticMarkup(React.createElement(PrivacyDrawer, { ...props, egressCapture }))).toContain('Independent egress capture');
  });

  test('shows the masked preview when a preflight is given', () => {
    const html = renderToStaticMarkup(React.createElement(PrivacyDrawer, { ...props, preflight }));
    expect(html).toContain('•••••• •••-•••• ••••');
    expect(html).not.toContain('No payload preview.');
  });
});
