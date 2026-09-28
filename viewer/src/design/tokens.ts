/**
 * Every style the panel uses, expressed as token references.
 *
 * Nothing in `src/` names a colour, a length or a font size. This module is
 * the only place that knows which token answers which question, and it knows
 * that by name - never by value - because the values live in
 * `design/tokens.json` and are emitted into `design/tokens.css` and
 * `design/tokens.ts`.
 *
 * ESLint rejects a hex literal or a px literal anywhere under `src/`, and
 * `design/build.ts` fails the build on the same thing for the file types ESLint
 * does not parse. A comment saying "use a token here" is not one of those.
 */
import type { CSSProperties } from 'react';
import { varRef } from '../../design/tokens';

/** `var(--medarx-color-panel)` */
export const color = {
  canvas: varRef('colors.canvas'),
  viewer: varRef('colors.viewer'),
  panel: varRef('colors.panel'),
  raised: varRef('colors.raised'),
  foreground: varRef('colors.foreground'),
  muted: varRef('colors.muted'),
  subtle: varRef('colors.subtle'),
  border: varRef('colors.border'),
  accent: varRef('colors.accent'),
  accentForeground: varRef('colors.accent-foreground'),
  approved: varRef('colors.approved'),
  blocked: varRef('colors.blocked'),
  caution: varRef('colors.caution'),
  focus: varRef('colors.focus'),
} as const;

export const hairline = varRef('border.hairline');

/* --------------------------------------------------------------- typography */

const headingMd = {
  fontFamily: varRef('typography.heading-md.fontFamily'),
  fontSize: varRef('typography.heading-md.fontSize'),
  fontWeight: varRef('typography.heading-md.fontWeight'),
  lineHeight: varRef('typography.heading-md.lineHeight'),
} as const;

const body = {
  fontFamily: varRef('typography.body.fontFamily'),
  fontSize: varRef('typography.body.fontSize'),
  fontWeight: varRef('typography.body.fontWeight'),
  lineHeight: varRef('typography.body.lineHeight'),
} as const;

const report = {
  fontFamily: varRef('typography.report.fontFamily'),
  fontSize: varRef('typography.report.fontSize'),
  fontWeight: varRef('typography.report.fontWeight'),
  lineHeight: varRef('typography.report.lineHeight'),
} as const;

const label = {
  fontFamily: varRef('typography.label.fontFamily'),
  fontSize: varRef('typography.label.fontSize'),
  fontWeight: varRef('typography.label.fontWeight'),
  lineHeight: varRef('typography.label.lineHeight'),
} as const;

const metadata = {
  fontFamily: varRef('typography.metadata.fontFamily'),
  fontSize: varRef('typography.metadata.fontSize'),
  fontWeight: varRef('typography.metadata.fontWeight'),
  lineHeight: varRef('typography.metadata.lineHeight'),
} as const;

export const typeStyles: Record<'heading' | 'body' | 'report' | 'label' | 'metadata', CSSProperties> = {
  heading: headingMd,
  body,
  report,
  label,
  metadata,
};

/* ------------------------------------------------------------------ spacing */

export const space = {
  xs: varRef('spacing.xs'),
  sm: varRef('spacing.sm'),
  md: varRef('spacing.md'),
  lg: varRef('spacing.lg'),
  xl: varRef('spacing.xl'),
} as const;

export const radius = {
  sm: varRef('rounded.sm'),
  md: varRef('rounded.md'),
  lg: varRef('rounded.lg'),
} as const;

/* ------------------------------------------------ the design's components */

/** `primary-button`, exactly as the front-matter specifies it. */
export const primaryButton = {
  background: varRef('components.primary-button.backgroundColor'),
  text: varRef('components.primary-button.textColor'),
  radius: varRef('components.primary-button.rounded'),
  minHeight: varRef('components.primary-button.minHeight'),
} as const;

/** `secondary-button`, exactly as the front-matter specifies it. */
export const secondaryButton = {
  background: varRef('components.secondary-button.backgroundColor'),
  text: varRef('components.secondary-button.textColor'),
  border: varRef('components.secondary-button.borderColor'),
  radius: varRef('components.secondary-button.rounded'),
  minHeight: varRef('components.secondary-button.minHeight'),
} as const;

/** `copilot-panel`, exactly as the front-matter specifies it. */
export const shell = {
  background: varRef('components.copilot-panel.backgroundColor'),
  border: varRef('components.copilot-panel.borderColor'),
  defaultWidth: varRef('components.copilot-panel.defaultWidth'),
} as const;

/** `report-editor`, exactly as the front-matter specifies it. */
export const editor = {
  background: varRef('components.report-editor.backgroundColor'),
  text: varRef('components.report-editor.textColor'),
  radius: varRef('components.report-editor.rounded'),
} as const;

/** The panel's usable range, which the design states in prose rather than in
 *  front-matter. Each carries its citation in `tokens.json`. */
export const panelRange = {
  minWidth: varRef('panel.minWidth'),
  maxWidth: varRef('panel.maxWidth'),
  step: varRef('panel.separatorStep'),
} as const;
