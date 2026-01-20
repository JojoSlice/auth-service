// ESLint security configuration for auth-proxy
// Used by the security CI pipeline to enforce security best practices

import security from 'eslint-plugin-security';
import tseslint from 'typescript-eslint';

export default [
  {
    files: ['**/*.ts', '**/*.js'],
    plugins: {
      security,
    },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      parser: tseslint.parser,
    },
    rules: {
      // ============================================
      // eslint-plugin-security rules
      // ============================================

      // Detect potential command injection
      'security/detect-child-process': 'error',

      // Detect eval() with variable
      'security/detect-eval-with-expression': 'error',

      // Detect non-literal fs.readFile
      'security/detect-non-literal-fs-filename': 'warn',

      // Detect non-literal regexes
      'security/detect-non-literal-regexp': 'warn',

      // Detect non-literal require
      'security/detect-non-literal-require': 'error',

      // Detect possible timing attacks
      'security/detect-possible-timing-attacks': 'error',

      // Detect pseudo-random bytes
      'security/detect-pseudoRandomBytes': 'warn',

      // Detect unsafe regex
      'security/detect-unsafe-regex': 'error',

      // Detect buffer() with no encoding
      'security/detect-buffer-noassert': 'error',

      // Detect new Buffer() usage
      'security/detect-new-buffer': 'error',

      // Detect object injection
      'security/detect-object-injection': 'warn',

      // Detect disabled security features
      'security/detect-disable-mustache-escape': 'error',

      // ============================================
      // Additional security-focused rules
      // ============================================

      // Disallow eval()
      'no-eval': 'error',

      // Disallow implied eval
      'no-implied-eval': 'error',

      // Disallow new Function()
      'no-new-func': 'error',

      // Disallow script URLs
      'no-script-url': 'error',

      // Require use of === and !==
      'eqeqeq': ['error', 'always'],

      // Disallow variable shadowing
      'no-shadow': 'warn',

      // Disallow use of undeclared variables
      'no-undef': 'error',

      // Require const for variables that are never reassigned
      'prefer-const': 'error',

      // Disallow var declarations
      'no-var': 'error',
    },
  },
];
