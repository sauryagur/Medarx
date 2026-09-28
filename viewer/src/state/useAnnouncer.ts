/**
 * One polite live region for the whole panel.
 *
 * The design requires that validation errors and blocked states be announced
 * without reading sensitive original values aloud. That is not a formatting
 * rule here, it is the only channel: every message that reaches this region is
 * built by `announcementFor` / `functionAnnouncement` in `panelState.ts`, out
 * of the closed vocabulary there, and neither of those functions can be handed
 * a payload, a field value or anything the clinician typed.
 *
 * `aria-live="polite"` rather than `assertive`: a blocked request is important
 * but not an emergency, and an assertive region interrupts whatever the screen
 * reader is in the middle of saying.
 */
import { useCallback, useRef, useState } from 'react';

export function useAnnouncer() {
  const [message, setMessage] = useState('');
  const region = useRef<HTMLDivElement | null>(null);

  const announce = useCallback((text: string) => {
    // Re-announcing an identical string is a no-op for most screen readers
    // unless the text actually changes, so a repeat is nudged with a trailing
    // space. It is a nudge, not a different message.
    setMessage((m) => (m === text ? `${text} ` : text));
  }, []);

  return { message, announce, region };
}
