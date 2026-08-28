<center><img src="docs/logo.webp" alt="" /></center>

# Untitled

> Information Line

## Conventions

- Hard tabs (tab stop 4) for all indentation in every code file:
	`.js`, `.jsx`, `.mjs`, `.json`, `.jsonl`, `.css`, `.html`, `.htmx`, `.md`
- LF line endings, UTF-8, and a single trailing newline — see `.editorconfig`
- `.jsonl` files are line-oriented: one JSON value per line, nothing to indent
- Markdown: blank lines around every heading, tab list indentation,
	and content above the first `H1` is allowed (e.g. the logo above)

## Tooling

- Prettier formats `.js`/`.jsx`/`.mjs`/`.json`/`.css`/`.html`/`.htmx` with tabs,
	no semicolons, and single quotes (`useTabs`, `tabWidth: 4`)
- ESLint + eslint-plugin-unicorn lint `.js`/`.mjs`/`.jsx` via `eslint.config.mjs`
- [markdownlint](https://github.com/DavidAnson/markdownlint) (markdownlint-cli2)
	lints `.md` via `.markdownlint.json`
- VS Code extensions: Prettier, ESLint, Markdownlint (DavidAnson.vscode-markdownlint),
	cSpell, EditorConfig — see `.vscode/extensions.json`

### Why markdown is not formatted by Prettier

Prettier has no tab support for Markdown — it rewrites list indentation to
spaces. So `.md` files are owned by markdownlint (auto-fix on save) plus the
editor tab settings (`.editorconfig`, `editor.insertSpaces: false`). Prettier
also has no `.jsonl` parser, so `.jsonl` stays line-oriented and is excluded
via `.prettierignore`.

## Scripts

- `npm run lint` — eslint on `lib/` + markdownlint on `README.md` and `docs/**/*.md`
- `npm run lint:fix` — the same, with auto-fixes
- `npm run format` — prettier check on `lib/` code plus the root config files
- `npm run format:fix` — prettier write on the same files
- `npm run check` — lint + format in one go

In VS Code, format-on-save runs the ESLint fixes first (`source.fixAll.eslint`)
and then Prettier, so the two never fight over layout: unicorn's formatting
rules (`template-indent`, `empty-brace-spaces`) are disabled in
`eslint.config.mjs`.

## Requirements

- Node 22.13+ (ESLint 10, eslint-plugin-unicorn, markdownlint-cli2)
