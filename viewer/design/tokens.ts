/*
 * GENERATED FILE - do not edit.
 * Source: viewer/design/tokens.json
 * Rebuild: cd viewer && bun run tokens
 *
 * The same tokens as tokens.css, for the places CSS cannot reach: a
 * getComputedStyle probe, a canvas-drawn diff mark, a Cornerstone overlay
 * label, and the contrast test. Deep-frozen because a token that can be
 * reassigned at runtime is a token with no source.
 */

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const inner of Object.values(value as Record<string, unknown>)) deepFreeze(inner);
  }
  return value;
}

export const tokens = deepFreeze({
  "color": {
    "canvas": "#08090A",
    "viewer": "#050607",
    "panel": "#111315",
    "raised": "#191C1F",
    "foreground": "#F5F7F8",
    "muted": "#A1A8AE",
    "subtle": "#737D85",
    "border": "#2A3034",
    "accent": "#80C9C5",
    "accentForeground": "#071413",
    "approved": "#78C69D",
    "blocked": "#F09985",
    "caution": "#E9C277",
    "focus": "#A5DAD7"
  },
  "type": {
    "headingLg": {
      "fontFamily": "Inter",
      "fontSize": "28px",
      "fontWeight": {},
      "lineHeight": {},
      "letterSpacing": "-0.02em"
    },
    "headingMd": {
      "fontFamily": "Inter",
      "fontSize": "20px",
      "fontWeight": {},
      "lineHeight": {}
    },
    "body": {
      "fontFamily": "Inter",
      "fontSize": "14px",
      "fontWeight": {},
      "lineHeight": {}
    },
    "report": {
      "fontFamily": "Inter",
      "fontSize": "15px",
      "fontWeight": {},
      "lineHeight": {}
    },
    "label": {
      "fontFamily": "Inter",
      "fontSize": "12px",
      "fontWeight": {},
      "lineHeight": {}
    },
    "metadata": {
      "fontFamily": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      "fontSize": "11px",
      "fontWeight": {},
      "lineHeight": {}
    }
  },
  "radius": {
    "sm": "4px",
    "md": "8px",
    "lg": "12px"
  },
  "spacing": {
    "s": "4px",
    "m": "8px",
    "d": "12px",
    "g": "20px",
    "l": "32px"
  },
  "panel": {
    "minWidth": "360px",
    "maxWidth": "560px",
    "separatorStep": "20px"
  },
  "component": {
    "primaryButton": {
      "backgroundColor": "#80C9C5",
      "textColor": "#071413",
      "rounded": "8px",
      "minHeight": "40px"
    },
    "secondaryButton": {
      "backgroundColor": "#191C1F",
      "textColor": "#F5F7F8",
      "borderColor": "#2A3034",
      "rounded": "8px",
      "minHeight": "40px"
    },
    "copilotPanel": {
      "backgroundColor": "#111315",
      "borderColor": "#2A3034",
      "defaultWidth": "400px"
    },
    "reportEditor": {
      "backgroundColor": "#191C1F",
      "textColor": "#F5F7F8",
      "rounded": "8px"
    }
  }
});

export type Tokens = typeof tokens;

/** Token path -> CSS custom property, for code that needs the var name itself. */
export const cssVar: Readonly<Record<string, string>> = deepFreeze({
  "border.hairline": "--medarx-border-hairline",
  "colors.accent": "--medarx-color-accent",
  "colors.accent-foreground": "--medarx-color-accent-foreground",
  "colors.approved": "--medarx-color-approved",
  "colors.blocked": "--medarx-color-blocked",
  "colors.border": "--medarx-color-border",
  "colors.canvas": "--medarx-color-canvas",
  "colors.caution": "--medarx-color-caution",
  "colors.focus": "--medarx-color-focus",
  "colors.foreground": "--medarx-color-foreground",
  "colors.muted": "--medarx-color-muted",
  "colors.panel": "--medarx-color-panel",
  "colors.raised": "--medarx-color-raised",
  "colors.subtle": "--medarx-color-subtle",
  "colors.viewer": "--medarx-color-viewer",
  "components.copilot-panel.backgroundColor": "--medarx-copilot-panel-background-color",
  "components.copilot-panel.borderColor": "--medarx-copilot-panel-border-color",
  "components.copilot-panel.defaultWidth": "--medarx-copilot-panel-default-width",
  "panel.maxWidth": "--medarx-panel-maxWidth",
  "panel.minWidth": "--medarx-panel-minWidth",
  "panel.separatorStep": "--medarx-panel-separatorStep",
  "components.primary-button.backgroundColor": "--medarx-primary-button-background-color",
  "components.primary-button.minHeight": "--medarx-primary-button-min-height",
  "components.primary-button.rounded": "--medarx-primary-button-rounded",
  "components.primary-button.textColor": "--medarx-primary-button-text-color",
  "rounded.lg": "--medarx-radius-lg",
  "rounded.md": "--medarx-radius-md",
  "rounded.sm": "--medarx-radius-sm",
  "components.report-editor.backgroundColor": "--medarx-report-editor-background-color",
  "components.report-editor.rounded": "--medarx-report-editor-rounded",
  "components.report-editor.textColor": "--medarx-report-editor-text-color",
  "components.secondary-button.backgroundColor": "--medarx-secondary-button-background-color",
  "components.secondary-button.borderColor": "--medarx-secondary-button-border-color",
  "components.secondary-button.minHeight": "--medarx-secondary-button-min-height",
  "components.secondary-button.rounded": "--medarx-secondary-button-rounded",
  "components.secondary-button.textColor": "--medarx-secondary-button-text-color",
  "spacing.lg": "--medarx-spacing-lg",
  "spacing.md": "--medarx-spacing-md",
  "spacing.sm": "--medarx-spacing-sm",
  "spacing.xl": "--medarx-spacing-xl",
  "spacing.xs": "--medarx-spacing-xs",
  "typography.body.fontFamily": "--medarx-type-body-font-family",
  "typography.body.fontSize": "--medarx-type-body-font-size",
  "typography.body.fontWeight": "--medarx-type-body-font-weight",
  "typography.body.lineHeight": "--medarx-type-body-line-height",
  "typography.heading-lg.fontFamily": "--medarx-type-heading-lg-font-family",
  "typography.heading-lg.fontSize": "--medarx-type-heading-lg-font-size",
  "typography.heading-lg.fontWeight": "--medarx-type-heading-lg-font-weight",
  "typography.heading-lg.letterSpacing": "--medarx-type-heading-lg-letter-spacing",
  "typography.heading-lg.lineHeight": "--medarx-type-heading-lg-line-height",
  "typography.heading-md.fontFamily": "--medarx-type-heading-md-font-family",
  "typography.heading-md.fontSize": "--medarx-type-heading-md-font-size",
  "typography.heading-md.fontWeight": "--medarx-type-heading-md-font-weight",
  "typography.heading-md.lineHeight": "--medarx-type-heading-md-line-height",
  "typography.label.fontFamily": "--medarx-type-label-font-family",
  "typography.label.fontSize": "--medarx-type-label-font-size",
  "typography.label.fontWeight": "--medarx-type-label-font-weight",
  "typography.label.lineHeight": "--medarx-type-label-line-height",
  "typography.metadata.fontFamily": "--medarx-type-metadata-font-family",
  "typography.metadata.fontSize": "--medarx-type-metadata-font-size",
  "typography.metadata.fontWeight": "--medarx-type-metadata-font-weight",
  "typography.metadata.lineHeight": "--medarx-type-metadata-line-height",
  "typography.report.fontFamily": "--medarx-type-report-font-family",
  "typography.report.fontSize": "--medarx-type-report-font-size",
  "typography.report.fontWeight": "--medarx-type-report-font-weight",
  "typography.report.lineHeight": "--medarx-type-report-line-height"
});

/** A 'var(--medarx-...)' reference for a token path. Throws on an unknown path,
 *  because a silently empty string renders as no styling at all. */
export function varRef(path: string): string {
  const name = cssVar[path];
  if (!name) throw new Error(`unknown Medarx token: ${path}`);
  return `var(${name})`;
}
