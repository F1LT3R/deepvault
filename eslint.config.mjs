import js from '@eslint/js'

export default [
	js.configs.recommended,
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
		ignores: ['node_modules', 'dist', '.vscode'],
	},
]
