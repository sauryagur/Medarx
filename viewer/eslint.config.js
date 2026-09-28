import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/**
 * The lint rule, not a convention.
 *
 * The design system has exactly one source of colour, length and type values:
 * `design/tokens.json`, emitted into `design/tokens.css` and `design/tokens.ts`.
 * A component that writes `#80C9C5` or `15px` creates a value with no edge back
 * to that source, so the day the accent changes the copy keeps the old one and
 * nothing fails. This file is what makes that a build-breaking mistake instead
 * of a review comment.
 *
 * Three selectors, because a value can be written three ways:
 *
 *   1. a string literal that looks like a colour or carries a length unit
 *      - `color: '#80C9C5'`, `width: '15px'`, `fontSize: '1rem'`
 *   2. the same thing inside a template literal
 *      - `border: `1px solid ${x}``
 *   3. a bare number under a CSS property name. This is the one that is easy to
 *      miss: React's CSS-in-JS appends `px` to a number, so `{ fontSize: 15 }`
 *      renders as `15px` and is exactly the defect this rule exists for. The
 *      property list is deliberately limited to properties where a unitless
 *      number is meaningless - `opacity`, `zIndex` and `flex` are unitless in
 *      CSS and are not design values, so they are not in it.
 *
 * `design/**` is excepted because it is the source, and `design/build.ts`
 * contains the patterns themselves as string literals. That exemption is the
 * whole of the escape hatch, and it is one directory.
 */
const COLOUR_OR_LENGTH = String.raw`#[0-9a-fA-F]{3,8}\b|\b\d+(?:\.\d+)?(?:px|rem|em|pt|vh|vw|vmin|vmax|ch|ex)\b|\b(?:rgb|rgba|hsl|hsla|hwb|lab|lch|oklch|oklab|color-mix)\s*\(`;

/**
 * CSS properties where React turns a bare number into a pixel length.
 * `opacity`, `zIndex`, `flex`, `flexGrow`, `order`, `lineHeight` and
 * `fontWeight` are unitless in CSS and are omitted for that reason - the type
 * roles supply their own line heights and weights as tokens.
 */
const LENGTH_PROPERTIES = [
  'background',
  'backgroundColor',
  'border',
  'borderBlock',
  'borderBlockEnd',
  'borderBlockStart',
  'borderBottom',
  'borderInline',
  'borderInlineEnd',
  'borderInlineStart',
  'borderLeft',
  'borderRadius',
  'borderRight',
  'borderTop',
  'borderWidth',
  'bottom',
  'boxShadow',
  'columnGap',
  'flexBasis',
  'gap',
  'height',
  'inlineSize',
  'inset',
  'left',
  'letterSpacing',
  'margin',
  'marginBlock',
  'marginBlockEnd',
  'marginBlockStart',
  'marginBottom',
  'marginInline',
  'marginInlineEnd',
  'marginInlineStart',
  'marginLeft',
  'marginRight',
  'marginTop',
  'maxHeight',
  'maxInlineSize',
  'maxWidth',
  'minHeight',
  'minInlineSize',
  'minWidth',
  'outlineOffset',
  'outlineWidth',
  'padding',
  'paddingBlock',
  'paddingBlockEnd',
  'paddingBlockStart',
  'paddingBottom',
  'paddingInline',
  'paddingInlineEnd',
  'paddingInlineStart',
  'paddingLeft',
  'paddingRight',
  'paddingTop',
  'right',
  'rowGap',
  'top',
  'width',
].join('|');

const MESSAGE = [
  'Medarx design values come from a token, not from a literal.',
  'A raw value here is a copy with no edge back to design/tokens.json, so the day the token',
  'changes this keeps the old one and nothing fails. Use varRef("<token path>") or',
  'var(--medarx-...) from the generated stylesheet.',
].join(' ');

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts', '**/*.tsx'],
    ignores: ['design/**'],
    languageOptions: {
      globals: { ...globals.browser, ...globals.es2022 },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: {
      'no-restricted-syntax': [
        'error',
        { selector: `Literal[value=/${COLOUR_OR_LENGTH}/]`, message: MESSAGE },
        { selector: `TemplateElement[value.raw=/${COLOUR_OR_LENGTH}/]`, message: MESSAGE },
        {
          // A bare number only. A string that starts with a digit (`'100%'`) is
          // caught by the string rules above, and is not a pixel length.
          selector: `Property[key.name=/^(${LENGTH_PROPERTIES})$/][value.type='Literal'][value.value=/^-?\\d+(\\.\\d+)?$/]`,
          message: `${MESSAGE} (React appends px to a bare number, so this renders as a pixel length.)`,
        },
      ],
      // The design says errors and blocked states are announced without reading
      // sensitive values aloud, and the Phase 1 rule on the Python side is that
      // response bodies never reach a log. Neither survives a console.log in the
      // browser, so the browser gets the same rule.
      'no-console': 'error',
      eqeqeq: ['error', 'smart'],
      // A parameter named with a leading underscore is the convention for
      // "required by the caller's shape, deliberately not read" - which is what
      // the OHIF manager bag is here.
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  {
    // The generated artefacts and the token build are the source, and are
    // exempt from the literal rule by design rather than by accident.
    files: ['design/**/*.ts'],
    languageOptions: { globals: { ...globals.node } },
    rules: { 'no-restricted-syntax': 'off' },
  },
  {
    files: ['design/**/*.test.ts', 'vite.config.ts', 'eslint.config.js'],
    languageOptions: { globals: { ...globals.node, ...globals.bun } },
  },
);
