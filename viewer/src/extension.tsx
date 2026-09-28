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
 * `getPanelModule` takes the three manager arguments OHIF passes every panel
 * module. This panel needs none of them: it renders state it is given and owns
 * no data fetching, because the boundary says the panel never computes
 * redaction, pseudonymisation, a date shift or a policy decision, and the
 * wire-up to the API belongs to the workstream that reads it.
 */
import type { Panel } from './ohif/types';
import { MedarxPanel } from './panels/MedarxPanel';
import type { MedarxPanelProps } from './panels/MedarxPanel';
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

export function getPanelModule(_managers: ManagerBag = {}): Panel[] {
  return [
    {
      name: MEDARX_PANEL_NAME,
      iconName: 'chat',
      iconLabel: 'Medarx',
      label: 'Medarx',
      component: (props: Partial<MedarxPanelProps>) => (
        <MedarxPanel
          {...props}
          studyLabel={props.studyLabel ?? 'No study association'}
          route={props.route ?? UNREAD_ROUTE}
          requestState={props.requestState ?? NO_REQUEST}
        />
      ),
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
