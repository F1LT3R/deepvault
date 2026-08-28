import js from '@eslint/js'
import unicorn from 'eslint-plugin-unicorn'

export default [
	js.configs.recommended,
	unicorn.configs.recommended,
	{
		languageOptions: {
			ecmaVersion: 'latest',
			sourceType: 'module',
			globals: {
				window: 'readonly',
				document: 'readonly',
				console: 'readonly',
				setTimeout: 'readonly',
				clearTimeout: 'readonly',
				setInterval: 'readonly',
				clearInterval: 'readonly',
				requestAnimationFrame: 'readonly',
				cancelAnimationFrame: 'readonly',
				fetch: 'readonly',
				URL: 'readonly',
				URLSearchParams: 'readonly',
				Math: 'readonly',
				performance: 'readonly',
				HTMLElement: 'readonly',
				CustomEvent: 'readonly',
				customElements: 'readonly',
			},
		},
		rules: {
			'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
			'no-var': 'error',
			'prefer-const': 'warn',
			'no-console': 'off',
		},
	},
	{
		// Unicorn overrides.
		// Formatting is owned by prettier — disable the unicorn rules that
		// rewrite layout prettier also rewrites, or the two will fight.
		// The rest are disabled because they are too opinionated for a
		// fresh bootstrap project (enable per project if wanted).
		rules: {
			// Layout rules — prettier owns these
			'unicorn/template-indent': 'off',
			'unicorn/empty-brace-spaces': 'off',
			// Bootstrap ergonomics
			'unicorn/no-empty-file': 'off',
			'unicorn/filename-case': 'off',
			'unicorn/expiring-todo-comments': 'off',
			'unicorn/name-replacements': 'off',
		},
	},
	{
		ignores: ['node_modules', 'dist', '.vscode'],
	},
]
