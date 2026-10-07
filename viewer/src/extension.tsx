/**
 * The OHIF extension entry point.
 *
 * This is an extension, not a fork. Nothing in `@ohif` is patched, vendored or
 * wrapped: the panel is a `panelModule` a mode places by id, and the mode's
 * `layoutTemplate` puts it in `rightPanels`. The drift check for that is one
 * command - `git diff` against the pinned tag shows no OHIF file - and it
 * cannot pass by accident, because no OHIF file is tracked in this repository
 * at all.
 *
 * The extension has no manager dependency. DraftReview reads only the
 * same-origin /v1 API and sends clinician-supplied report_text only after an
 * explicit preflight action; it performs no local redaction or policy work.
 */
import { useEffect, useState } from 'react';
import type { Panel } from './ohif/types';
import { MedarxPanel } from './panels/MedarxPanel';
import type { MedarxPanelProps } from './panels/MedarxPanel';
import { DraftReview } from './panels/DraftReview';
import { panelStore } from './state/panelStore';
import type { RequestState, RouteState } from './state/panelState';

export const MEDARX_EXTENSION_NAME = 'medarx';
export const MEDARX_PANEL_NAME = 'medarxPanel';

type ManagerBag = {
  servicesManager?: unknown;
  commandsManager?: unknown;
  extensionManager?: unknown;
};

/**
 * The panel reads these from the props OHIF hands it rather than from a store
 * of its own, so a test - and the harness - can drive every state the panel can
 * be in without a server, a study, or a network.
 *
 * Both default to a value that refuses to assert anything: an unread route and
 * an unmade request. A panel that opened showing "Strict local" and "Approved"
 * because those were the convenient defaults would be claiming two privacy
 * states the deployment never evaluated.
 */
export const UNREAD_ROUTE: RouteState = { kind: 'unknown' };
export const NO_REQUEST: RequestState = { kind: 'idle' };

function DraftPanel(props: Partial<MedarxPanelProps>) {
  const [requestState, setRequestState] = useState(props.requestState ?? NO_REQUEST);
  useEffect(() => {
    setRequestState(props.requestState ?? NO_REQUEST);
  }, [props.requestState]);

  return (
    <MedarxPanel
      {...props}
      studyLabel={props.studyLabel ?? 'No study association'}
      route={props.route ?? UNREAD_ROUTE}
      requestState={requestState}
    >
      <DraftReview
        studyContext={props.studyContext}
        scope={props.scope}
        apiBase={props.apiBase}
        onRequestState={setRequestState}
      />
    </MedarxPanel>
  );
}

export function getPanelModule(_managers: ManagerBag = {}): Panel[] {
  return [
    {
      name: MEDARX_PANEL_NAME,
      iconName: 'chat',
      iconLabel: 'Medarx',
      label: 'Medarx',
      component: DraftPanel,
    },
  ];
}

type CommandHandler = (args: Record<string, unknown>) => void;

/**
 * Commands, and they are real ones. `medarxTogglePanel` and
 * `medarxSetPanelWidth` write the same store the panel reads, so a toolbar
 * button or a shortcut wired to them moves the panel the same way the panel's
 * own controls do. A command that acknowledged the press and did nothing would
 * be the "enabled and ignored" failure in a different costume, and it is the
 * one thing this workstream refuses to ship.
 */
export function getCommands(): { definitions: Record<string, CommandHandler> } {
  return {
    definitions: {
      medarxTogglePanel: () => panelStore.toggleCollapsed(),
      medarxSetPanelWidth: (args) => {
        const width = Number(args.width);
        if (!Number.isFinite(width)) {
          throw new Error(`medarxSetPanelWidth: width must be a number, got ${JSON.stringify(args.width)}`);
        }
        panelStore.setWidth(width);
      },
    },
  };
}

/**
 * The default export is what the host actually consumes.
 *
 * OHIF's plugin loader (`platform/app/src/pluginImports.js`, generated from
 * `pluginConfig.json` at build time) does `imported.default` and nothing else,
 * so an extension module that only has named exports registers as `undefined`
 * and every panel reference to it fails with "is not a valid entry for an
 * extension module". `id` is the other half: `ExtensionManager` builds panel
 * ids as `${id}.panelModule.${name}`, so this value and the mode's
 * `rightPanels` entry are one string that has to agree.
 *
 * `MEDARX_EXTENSION_NAME` ('medarx') is what the mode config writes into that
 * id, and `panelId()` in `src/ohif/types.ts` builds it. They are checked
 * against each other rather than kept honest by hand — see
 * `viewer/ohif/verify_mount.mjs`.
 */
export const MEDARX_EXTENSION_ID = `@ohif/extension-${MEDARX_EXTENSION_NAME}`;

const medarxExtension = {
  id: MEDARX_EXTENSION_ID,
  getPanelModule,
  getCommands,
};

export default medarxExtension;
