/**
 * The development harness.
 *
 * This is a stand-in for the OHIF host, and it exists for one reason: to show
 * that the panel is a sibling of the image viewport and leaves it alone. It
 * renders a study header bar, a viewport with its own controls and its own
 * keyboard handling, and the Medarx panel beside it - and it counts what the
 * viewport received, so "the viewer is still usable" is a number on screen
 * rather than an assertion in a comment.
 *
 * It is a harness, not a viewer. There is no DICOM here, no image data and no
 * study: the viewport is a labelled box, and nothing in it is a stand-in for a
 * finding. Running the real OHIF mode is the composition root's job, and
 * `.docs/phase2-plan.md` §WS2 item 4 owns it.
 */
import { useEffect, useRef, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { Button, Divider } from '../design/primitives';
import { color, hairline, radius, space, typeStyles } from '../design/tokens';

export function ViewerHarness({ children }: { children: ReactNode }) {
  const [viewportKeys, setViewportKeys] = useState(0);
  const [tool, setTool] = useState('W/L');
  const viewport = useRef<HTMLDivElement | null>(null);

  // A host-level key handler, the way OHIF's own shortcuts work: they fire when
  // the viewer owns focus. If the panel swallowed them, this count would stop
  // moving while the viewport has focus. It is on `document` rather than on the
  // viewport element so that a key which the panel stopped propagating would
  // still be counted - which is the thing being checked.
  useEffect(() => {
    const onKey = () => {
      if (!viewport.current?.contains(document.activeElement)) return;
      setViewportKeys((n) => n + 1);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div style={ROOT}>
      <StudyHeader />
      <div style={BODY}>
        <div
          ref={viewport}
          tabIndex={0}
          role="region"
          aria-label="Image viewport (harness stand-in)"
          style={VIEWPORT}
        >
          <div style={VIEWPORT_TOOLS}>
            <Button tone="secondary" onClick={() => setTool('W/L')}>
              Window / level
            </Button>
            <Button tone="secondary" onClick={() => setTool('Zoom')}>
              Zoom
            </Button>
            <Button tone="secondary" onClick={() => setTool('Pan')}>
              Pan
            </Button>
            <Divider orientation="vertical" />
            <span style={typeStyles.metadata}>
              active tool {tool} · keys received while focused {viewportKeys}
            </span>
          </div>
          <div style={VIEWPORT_FIELD}>
            <p style={{ ...typeStyles.body, color: color.muted, margin: 0, textAlign: 'center' }}>
              No image data in this harness.
              <br />
              The box stands in for the viewport so the panel can be shown beside it, not over it.
            </p>
          </div>
        </div>
        {children}
      </div>
    </div>
  );
}

function StudyHeader() {
  return (
    <header style={STUDY_HEADER}>
      <span style={{ ...typeStyles.label, color: color.foreground }}>Study (harness stand-in)</span>
      <span style={{ ...typeStyles.metadata, color: color.muted }}>
        The Medarx panel does not read, display or log any patient or study identifier.
      </span>
    </header>
  );
}

const ROOT: CSSProperties = {
  // A percentage, not `100vh`: the emitted stylesheet gives `html`, `body` and
  // `#medarx-root` a definite height, and a definite parent is what lets the
  // panel and the drawer resolve their own percentage heights. An
  // auto-height root makes every `100%` below it content-driven, which is how a
  // panel ends up taller than the viewport it is supposed to sit inside.
  height: '100%',
  display: 'flex',
  flexDirection: 'column',
  background: color.canvas,
  color: color.foreground,
  fontFamily: typeStyles.body.fontFamily,
};

const STUDY_HEADER: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: space.md,
  padding: `${space.sm} ${space.md}`,
  borderBottom: `${hairline} solid ${color.border}`,
  flex: 'none',
};

const BODY: CSSProperties = {
  display: 'flex',
  flexDirection: 'row',
  flex: '1 1 auto',
  minHeight: 0,
  // The viewport is the flexible sibling and the panel is not: this is the
  // whole of "the panel does not displace the study". `minWidth: 0` stops the
  // viewport refusing to shrink below its content, which is the usual way a
  // right-hand panel pushes an image out of view.
  alignItems: 'stretch',
};

const VIEWPORT: CSSProperties = {
  flex: '1 1 auto',
  minWidth: 0,
  display: 'flex',
  flexDirection: 'column',
  background: color.viewer,
  padding: space.md,
  gap: space.md,
};

const VIEWPORT_TOOLS: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: space.xs,
  flex: 'none',
  flexWrap: 'wrap',
};

const VIEWPORT_FIELD: CSSProperties = {
  flex: '1 1 auto',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  border: `${hairline} dashed ${color.border}`,
  borderRadius: radius.lg,
  minHeight: 0,
};
