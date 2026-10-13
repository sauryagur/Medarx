/**
 * The Medarx extension **as the real OHIF viewer loads it**.
 *
 * `src/extension.tsx` is the panel and its commands, and it is deliberately
 * host-agnostic: it renders state it is handed and imports nothing from OHIF,
 * which is what let the design system and the shell be built and tested without
 * a viewer. This file is the other half — the thin adapter that knows it is
 * running inside a genuine OHIF mode:
 *
 *   * it reads the study the mode is actually displaying, so the panel header's
 *     study association is the truth and not a fixture;
 *   * it reads the in-force policy mode from `GET /v1/policy`, read-only;
 *   * it hands the result to the same `MedarxPanel` component.
 *
 * It is the file `pluginConfig.json` points at, and it is the only place in the
 * viewer that imports `@ohif/core`.
 *
 * ## What it deliberately does not do
 *
 * No pixels. Nothing here reads a viewport, an image, a frame or a DICOM
 * attribute beyond the study's UID, and nothing here hands study data to the
 * Medarx API. The panel is a display surface: no redaction, no pseudonymisation,
 * no date shift, no policy decision is computed on this side of the boundary.
 * The route is read, never chosen.
 */
import { useEffect, useState } from 'react';
import * as React from 'react';
import { useSystem } from '@ohif/core';
import {
  getCommands,
  getPanelModule,
  MEDARX_EXTENSION_ID,
  MEDARX_PANEL_NAME,
  NO_REQUEST,
  UNREAD_ROUTE,
} from '../src/extension';
import { MedarxPanel } from '../src/panels/MedarxPanel';
import { DraftReview } from '../src/panels/DraftReview';
import type { RouteState } from '../src/state/panelState';
import { readPolicyRoute } from './policyRoute';

/**
 * The deployment's synthetic study mapping. This is the **only** place the
 * adapter may learn a study reference or a scope from: the panel must never
 * derive either from a DICOM attribute, so the mapping is keyed on the study
 * UID the mode is displaying and closed over the seeded synthetic studies the
 * backend actually knows.
 *
 * The key is the DICOM `StudyInstanceUID` of the seeded synthetic study
 * produced by `seed_study.py` (`UID_ROOT + "1.1"` — the same UID `mount.sh`
 * prints in the demo URL). The value is the backend seed's own study reference
 * and its declared scope string (see `backend/tests/conftest.py`, whose
 * `SCOPE` is exactly this): the study reference the backend's pseudonym /
 * policy path expects and the scope header it authorises. A UID the deployment
 * has not seeded — any real study — is absent from this table, and the adapter
 * then hands `undefined` down so the panel says the draft is unavailable
 * rather than inventing a study association.
 *
 * StudyInstanceUID remains, strictly, a technical label for the panel header;
 * it is not a field DraftReview ever reads, and it is not PHI the panel holds.
 */
const SYNTHETIC_STUDIES: Readonly<
  Record<string, { readonly studyReference: string; readonly scope: string; readonly modality: string }>
> = {
  // The seeded synthetic phantom (CT, SERIES "SYNTHETIC AXIAL 256X256").
  '1.2.826.0.1.3680043.8.498.1138.900.1.1': {
    studyReference: 'STUDY-SYN-000041',
    scope: 'scope:study:STUDY-SYN-000041,scope:function:Draft',
    modality: 'CT',
  },
};

/**
 * The study the mode is displaying, as a UID.
 *
 * A UID and not a patient name, deliberately. The panel is not the patient
 * banner — OHIF's own header is, and it is three lines above this one — and the
 * design's rule is that no DICOM attribute reaches this panel's DOM. The study
 * scope is a technical identifier; it is the thing a reader needs to confirm
 * that the panel is talking about the study on screen.
 *
 * `HangingProtocolService.getState().activeStudyUID` is the mode's own answer to
 * "which study am I showing", so it cannot drift from the viewport.
 */
function useStudyInstanceUID(): string | null {
  const { servicesManager } = useSystem();
  const [uid, setUid] = useState<string | null>(null);

  useEffect(() => {
    const service = servicesManager?.services?.hangingProtocolService as
      | {
          getState?: () => { activeStudyUID?: string };
          subscribe?: (event: string, cb: () => void) => { unsubscribe: () => void };
          EVENTS?: Record<string, string>;
        }
      | undefined;
    if (!service?.getState) {
      return;
    }

    const read = () => {
      const state = service.getState?.();
      setUid(state?.activeStudyUID ?? null);
    };
    read();

    const event = service.EVENTS?.PROTOCOL_CHANGED;
    const subscription = event ? service.subscribe?.(event, read) : undefined;
    return () => subscription?.unsubscribe?.();
  }, [servicesManager]);

  return uid;
}

function MedarxPanelInMode() {
  const studyInstanceUID = useStudyInstanceUID();
  const [route, setRoute] = useState<RouteState>(UNREAD_ROUTE);
  // Real request state, not a constant: DraftReview reports server-derived
  // states through its callback and this is what keeps the header chip honest.
  const [requestState, setRequestState] = useState(NO_REQUEST);

  useEffect(() => {
    const controller = new AbortController();
    readPolicyRoute(undefined, controller.signal).then(setRoute);
    return () => controller.abort();
  }, []);

  // The synthetic context is looked up and never derived. An unseeded study —
  // or no study at all — yields `undefined`, so DraftReview renders its
  // "unavailable until the host supplies a synthetic study reference" notice.
  const synthetic = studyInstanceUID ? SYNTHETIC_STUDIES[studyInstanceUID] : undefined;

  return (
    <MedarxPanel
      studyLabel={studyInstanceUID ? `Study ${studyInstanceUID}` : 'No study association'}
      route={route}
      requestState={requestState}
    >
      <DraftReview
        studyContext={
          synthetic ? { study_reference: synthetic.studyReference, modality: synthetic.modality } : undefined
        }
        scope={synthetic?.scope}
        onRequestState={setRequestState}
      />
    </MedarxPanel>
  );
}

/**
 * The same panel module `src/extension.tsx` returns, with the component
 * replaced by the connected one. Everything else — the name, the icon, the
 * label, and both commands — is the panel's own, unchanged.
 */
export function getConnectedPanelModule() {
  return getPanelModule().map(entry =>
    entry.name === MEDARX_PANEL_NAME ? { ...entry, component: MedarxPanelInMode } : entry,
  );
}

const medarxExtension = {
  id: MEDARX_EXTENSION_ID,
  getPanelModule: getConnectedPanelModule,
  getCommands,
};

export default medarxExtension;
