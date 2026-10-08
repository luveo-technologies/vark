import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import security from 'eslint-plugin-security';

/**
 * Flat ESLint config: core recommended + typed TS rules + security plugin.
 * A few security-plugin rules are intentionally relaxed below — each with a
 * rationale. This codebase IS a firewall: dynamic property access, subprocess
 * execution and filesystem access behind capability checks are the product,
 * not accidents. The rules stay ON everywhere except the justified cases.
 */
export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', 'sbom.json', 'coverage/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  security.configs.recommended,
  {
    rules: {
      // Dynamic access on validated/unknown-shape JSON payloads is the norm
      // in scanners and audit code; TypeScript's own index checks still apply.
      'security/detect-object-injection': 'off',
      // console output is the CLI's entire job.
      'no-console': 'off',
      // Rest-destructuring omission (`const { hash, prevHash: _, ...body }`)
      // is the standard way to strip keys before re-serialising; the removed
      // siblings are intentionally unused.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { ignoreRestSiblings: true, argsIgnorePattern: '^_' },
      ],
    },
  },
);
