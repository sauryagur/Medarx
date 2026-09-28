/**
 * The OHIF extension surface this panel plugs into, transcribed from the
 * pinned release rather than remembered.
 *
 * `@ohif/core@3.13.10` is declared as a peer dependency and is **not** imported
 * at runtime: the published package's `types` field points at
 * `src/types/index.ts`, and that file is not in the tarball, so importing a
 * type from it fails to compile. The two shapes below were therefore read out
 * of the pinned tag rather than invented, and the sources are named so the next
 * person can check them in one command:
 *
 *   curl -s https://raw.githubusercontent.com/OHIF/Viewers/v3.13.10/platform/core/src/types/PanelModule.ts
 *   curl -s https://raw.githubusercontent.com/OHIF/Viewers/v3.13.10/platform/core/src/services/PanelService/PanelService.tsx
 *
 * Read 2026-09-28. If OHIF is upgraded, these are the two files to re-read.
 */
import type { FC } from 'react';

export type Panel = {
  id?: string;
  name: string;
  iconName: string;
  iconLabel: string;
  label: string;
  component: FC;
};

/** `PanelService.tsx` at v3.13.10. */
export enum PanelPosition {
  Left = 'left',
  Right = 'right',
  Bottom = 'bottom',
}

/** The id a mode's `layoutTemplate` refers to: `<extension>.panelModule.<name>`. */
export const panelId = (extensionName: string, panelName: string) =>
  `@ohif/extension-${extensionName}.panelModule.${panelName}`;
