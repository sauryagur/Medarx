/**
 * The panel's presentation state, in one place.
 *
 * Width and collapse live in a store rather than in the panel's own `useState`
 * because OHIF can drive the panel from outside it - a toolbar button, a
 * shortcut, a mode's `customDisplayStudy` - and a control that cannot is the
 * "enabled and ignored" failure the function switcher exists to avoid. The
 * commands in `src/extension.ts` write here; the panel reads from here; there
 * is no second copy.
 *
 * The bounds are read from the generated token module rather than written here,
 * because a bound written here is a bound that survives a token change.
 * `design/tokens.css` cannot be read synchronously in a module body - and a
 * `getComputedStyle` probe would make the first render wrong - which is exactly
 * the case `design/tokens.ts` exists for.
 *
 * Nothing here is persisted. `localStorage` is not used anywhere in this viewer
 * and must not be: a saved width is harmless, but the same mechanism holding a
 * draft would write PHI to disk outside the audit log's storage policy, with no
 * retention rule and no purge path.
 */
import { useSyncExternalStore } from 'react';
import { tokens } from '../../design/tokens';

const px = (v: string): number => {
  const n = Number.parseFloat(v);
  if (Number.isNaN(n)) throw new Error(`Medarx panel geometry token is not a length: ${v}`);
  return n;
};

export const PANEL_MIN = px(tokens.panel.minWidth);
export const PANEL_MAX = px(tokens.panel.maxWidth);
export const PANEL_DEFAULT = px(tokens.component.copilotPanel.defaultWidth);
/** The arrow-key step for the resize separator: the spacing step `lg`, so the
 *  control moves by a distance the design system already defines. */
export const PANEL_STEP = px(tokens.panel.separatorStep);

if (!(PANEL_MIN <= PANEL_DEFAULT && PANEL_DEFAULT <= PANEL_MAX)) {
  throw new Error(
    `Medarx panel geometry tokens are out of order: min ${PANEL_MIN}, default ${PANEL_DEFAULT}, max ${PANEL_MAX}.`,
  );
}

export type PanelSnapshot = { width: number; collapsed: boolean };

let snapshot: PanelSnapshot = { width: PANEL_DEFAULT, collapsed: false };
const listeners = new Set<() => void>();
const emit = () => {
  for (const listener of listeners) listener();
};

const clamp = (n: number): number => Math.min(PANEL_MAX, Math.max(PANEL_MIN, n));

export const panelStore = {
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  get(): PanelSnapshot {
    return snapshot;
  },
  setWidth(next: number): void {
    const width = clamp(next);
    if (width === snapshot.width) return;
    snapshot = { ...snapshot, width };
    emit();
  },
  setCollapsed(collapsed: boolean): void {
    if (collapsed === snapshot.collapsed) return;
    snapshot = { ...snapshot, collapsed };
    emit();
  },
  toggleCollapsed(): void {
    panelStore.setCollapsed(!snapshot.collapsed);
  },
};

export function usePanelSnapshot(): PanelSnapshot {
  return useSyncExternalStore(panelStore.subscribe, panelStore.get, panelStore.get);
}
