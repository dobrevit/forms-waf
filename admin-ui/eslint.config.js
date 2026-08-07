// R-22: `npm run lint` was declared in package.json but no configuration existed,
// so linting had never run. The eslint/typescript-eslint/react-hooks plugins were
// already in devDependencies; this wires them up.
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'eslint.config.js'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      // Surfaced as warnings for now: the goal of this change is to make linting
      // possible and gate on errors, not to reformat the codebase in one commit.
      '@typescript-eslint/no-explicit-any': 'warn',
      // shadcn/ui components use `interface XProps extends React.HTMLAttributes<T> {}`
      // as an extension point. That is deliberate, so warn rather than error.
      '@typescript-eslint/no-empty-object-type': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  }
)
