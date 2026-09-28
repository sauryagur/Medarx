/**
 * Pointer and keyboard handling for the resize separator.
 *
 * The bounds, the step and the width itself all come from the store, so a
 * token change moves the edges and this file does not change with it. Only the
 * transient drag origin lives here: it is input state that exists between a
 * pointer-down and a pointer-up and has no meaning once the drag is over.
 *
 * The panel is on the right, so dragging its left edge toward the left widens
 * it and `ArrowLeft` widens it. A separator that moved the other way would be
 * a control whose direction contradicts the panel it is attached to.
 */
import { useCallback, useRef } from 'react';
import type { KeyboardEvent, PointerEvent } from 'react';
import { PANEL_MAX, PANEL_MIN, PANEL_STEP, panelStore } from './panelStore';

export function useResize(width: number) {
  const dragOrigin = useRef<{ pointerX: number; startWidth: number } | null>(null);

  const onPointerDown = useCallback(
    (event: PointerEvent<HTMLDivElement>) => {
      event.currentTarget.setPointerCapture(event.pointerId);
      dragOrigin.current = { pointerX: event.clientX, startWidth: width };
    },
    [width],
  );

  const onPointerMove = useCallback((event: PointerEvent<HTMLDivElement>) => {
    if (!dragOrigin.current) return;
    panelStore.setWidth(dragOrigin.current.startWidth - (event.clientX - dragOrigin.current.pointerX));
  }, []);

  const onPointerUp = useCallback((event: PointerEvent<HTMLDivElement>) => {
    dragOrigin.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }, []);

  const onKeyDown = useCallback((event: KeyboardEvent<HTMLDivElement>) => {
    const widen: Record<string, number> = {
      ArrowLeft: PANEL_STEP,
      ArrowUp: PANEL_STEP,
      ArrowRight: -PANEL_STEP,
      ArrowDown: -PANEL_STEP,
    };
    const step = widen[event.key];
    if (step !== undefined) {
      event.preventDefault();
      panelStore.setWidth(panelStore.get().width + step);
    } else if (event.key === 'Home') {
      event.preventDefault();
      panelStore.setWidth(PANEL_MIN);
    } else if (event.key === 'End') {
      event.preventDefault();
      panelStore.setWidth(PANEL_MAX);
    }
  }, []);

  return { onPointerDown, onPointerMove, onPointerUp, onKeyDown };
}
