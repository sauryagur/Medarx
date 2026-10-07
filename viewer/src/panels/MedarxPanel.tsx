/**
 * The panel shell.
 *
 * A flex sibling of the viewer's image viewport - never an overlay on it. The
 * design's first principle is that the study stays in view: the panel takes
 * space, the viewport re-fits, and nothing is drawn over the image, the study
 * header or OHIF's tools. There is no `position: absolute` and no z-index here
 * at all, and the harness in `src/harness` exists to demonstrate that the host
 * keeps its own focus, shortcuts and controls while the panel is open, resized
 * and collapsed.
 *
 * It is an `<aside aria-label>` rather than a `role="dialog"`, so assistive
 * technology treats it as a region of the page and does not move the user into
 * a modal context the design has not asked for. Nothing here traps focus: the
 * design traps focus only during the modal privacy review, which is a different
 * screen in a different phase.
 *
 * The panel owns exactly one live region, because a page that has two is a page
 * whose announcements race.
 */
import { useCallback, useEffect, useState } from 'react';
import type { CSSProperties, KeyboardEvent, PointerEvent, ReactNode, RefObject } from 'react';
import { Button, VisuallyHidden } from '../design/primitives';
import { FunctionNote, FunctionSwitch, functionAnnouncement, tabDomId } from './FunctionSwitch';
import { AVAILABLE } from './FunctionSwitch';
import type { FunctionName } from './FunctionSwitch';
import { PanelHeader } from './PanelHeader';
import { PrivacyDrawer } from './PrivacyDrawer';
import type { DraftReviewProps } from './DraftReview';
import { color, hairline, shell, space, typeStyles } from '../design/tokens';
import { announcementFor } from '../state/panelState';
import type { RequestState, RouteState } from '../state/panelState';
import { useAnnouncer } from '../state/useAnnouncer';
import { usePanelSnapshot, panelStore, PANEL_MAX, PANEL_MIN } from '../state/panelStore';
import { useResize } from '../state/useResize';

export type MedarxPanelProps = {
  /** A study association already reduced to something that is not an
   *  identifier. The panel never derives one from a study object. */
  studyLabel: string;
  route: RouteState;
  requestState: RequestState;
  children?: ReactNode;
  /** Synthetic study-scoped authorization supplied by the host; never inferred from DICOM. */
  studyContext?: DraftReviewProps['studyContext'];
  scope?: string;
  /** Same-origin API prefix; defaults to /v1. */
  apiBase?: string;
};

function LiveRegion({ region, message }: { region: RefObject<HTMLDivElement | null>; message: string }) {
  return (
    <div ref={region} role="status" aria-live="polite" aria-atomic="true" className="medarx-sr-only">
      {message}
    </div>
  );
}

function CollapsedRail({ onExpand }: { onExpand: () => void }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: space.sm,
        paddingBlock: space.md,
        background: shell.background,
        borderLeft: `${hairline} solid ${shell.border}`,
        width: space.xl,
        flex: 'none',
      }}
    >
      <Button tone="secondary" onClick={onExpand}>
        <span aria-hidden="true">‹</span>
        <VisuallyHidden>Show the Medarx panel</VisuallyHidden>
      </Button>
      <span style={{ ...typeStyles.metadata, color: color.muted, writingMode: 'vertical-rl' }}>Medarx</span>
    </div>
  );
}

function Separator({
  width,
  minWidth,
  maxWidth,
  onKeyDown,
  onPointerDown,
  onPointerMove,
  onPointerUp,
}: {
  width: number;
  minWidth: number;
  maxWidth: number;
  onKeyDown: (e: KeyboardEvent<HTMLDivElement>) => void;
  onPointerDown: (e: PointerEvent<HTMLDivElement>) => void;
  onPointerMove: (e: PointerEvent<HTMLDivElement>) => void;
  onPointerUp: (e: PointerEvent<HTMLDivElement>) => void;
}) {
  return (
    <div
      // A separator, not a slider: it moves a boundary rather than setting a
      // value, and aria-valuenow on a separator is the honest way to say so.
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize the Medarx panel"
      aria-valuenow={width}
      aria-valuemin={minWidth}
      aria-valuemax={maxWidth}
      tabIndex={0}
      onKeyDown={onKeyDown}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      style={{
        width: space.lg,
        flex: 'none',
        display: 'flex',
        justifyContent: 'center',
        cursor: 'col-resize',
        touchAction: 'none',
        background: 'transparent',
      }}
    >
      <div style={{ width: hairline, background: color.border, alignSelf: 'stretch' }} />
    </div>
  );
}

export function MedarxPanel({ studyLabel, route, requestState, children }: MedarxPanelProps) {
  const { width, collapsed } = usePanelSnapshot();
  const { onPointerDown, onPointerMove, onPointerUp, onKeyDown } = useResize(width);
  const { message, announce, region } = useAnnouncer();
  const [activeFunction, setActiveFunction] = useState<FunctionName>('Draft');
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    announce(announcementFor(requestState));
  }, [requestState, announce]);

  const selectFunction = useCallback(
    (fn: FunctionName) => {
      setActiveFunction(fn);
      announce(`Switched to ${fn}.`);
    },
    [announce],
  );

  if (collapsed) {
    return (
      <div style={ROW}>
        <CollapsedRail onExpand={() => panelStore.toggleCollapsed()} />
        <LiveRegion region={region} message={message} />
      </div>
    );
  }

  return (
    <div style={ROW}>
      <Separator
        width={width}
        minWidth={PANEL_MIN}
        maxWidth={PANEL_MAX}
        onKeyDown={onKeyDown}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
      />
      <aside
        aria-label="Medarx copilot"
        data-testid="medarx-panel"
        style={{
          width: `${width}px`,
          maxWidth: '100%',
          // Definite height, and a scroll container, so the drawer takes from
          // the panel's own space instead of growing the panel past the
          // viewport. A panel that grows with its content is a panel that
          // pushes the study out of view.
          height: '100%',
          minHeight: 0,
          display: 'flex',
          flexDirection: 'column',
          background: shell.background,
          borderLeft: `${hairline} solid ${shell.border}`,
          color: color.foreground,
          fontFamily: typeStyles.body.fontFamily,
          fontSize: typeStyles.body.fontSize,
          lineHeight: typeStyles.body.lineHeight,
          overflow: 'hidden',
        }}
      >
        <PanelHeader
          studyLabel={studyLabel}
          route={route}
          requestState={requestState}
          drawerOpen={drawerOpen}
          onToggleDrawer={() => setDrawerOpen((v) => !v)}
          onToggleCollapsed={() => panelStore.toggleCollapsed()}
        />

        <FunctionSwitch
          active={activeFunction}
          onSelect={selectFunction}
          onRefused={(fn) => announce(functionAnnouncement(fn))}
          onInspect={(fn) => (AVAILABLE[fn] ? undefined : announce(functionAnnouncement(fn)))}
        />
        <FunctionNote />

        <div
          id="medarx-function-panel"
          role="tabpanel"
          aria-labelledby={tabDomId(activeFunction)}
          tabIndex={0}
          style={PANEL_BODY}
        >
          {children ?? (
            <p style={{ ...typeStyles.report, color: color.muted, margin: 0 }}>
              The Draft function is the only one in this version. Its source, privacy review and draft
              comparison arrive with the workstream that builds them; this panel is the shell they are
              built inside.
            </p>
          )}
        </div>

        <PrivacyDrawer
          route={route}
          requestState={requestState}
          open={drawerOpen}
          functionName={activeFunction}
        />

        <LiveRegion region={region} message={message} />
      </aside>
    </div>
  );
}

const ROW: CSSProperties = {
  display: 'flex',
  flexDirection: 'row',
  flex: 'none',
  height: '100%',
  minHeight: 0,
};

const PANEL_BODY: CSSProperties = {
  flex: '1 1 auto',
  minHeight: 0,
  overflowY: 'auto',
  padding: space.md,
  display: 'flex',
  flexDirection: 'column',
  gap: space.md,
};
