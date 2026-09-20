import crypto from 'node:crypto'

// The alphabet is the rule, not a hand-picked list: every Node cipher whose
// family is below and whose mode is ctr/cbc/ofb/cfb. Excluded by rule:
// ecb (pattern leak); gcm/ccm/siv/poly1305 (authenticated — a tag is a cheap
// per-guess passphrase oracle, and the only oracle this format allows is the
// innermost tar check); xts/wrap (not data ciphers); cfb1/cfb8 (non-standard
// granularity). Do not add or remove rows; the table must match the rule.

export const MAX_64BIT_BYTES = 4294967296

const MODES = ['ctr', 'cbc', 'ofb', 'cfb']

// 64-bit-block ciphers: after 2^32 bytes of keystream reuse risk becomes
// non-negligible, so stacks containing them cap vault size at 4 GiB.
const FAMILIES = [
	{
		token: 'a128',
		prefix: 'aes-128-',
		keylen: 16,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'core',
	},
	{
		token: 'a192',
		prefix: 'aes-192-',
		keylen: 24,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'core',
	},
	{
		token: 'a256',
		prefix: 'aes-256-',
		keylen: 32,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'core',
	},
	{
		token: 'ar128',
		prefix: 'aria-128-',
		keylen: 16,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'build',
	},
	{
		token: 'ar192',
		prefix: 'aria-192-',
		keylen: 24,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'build',
	},
	{
		token: 'ar256',
		prefix: 'aria-256-',
		keylen: 32,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'build',
	},
	{
		token: 'cm128',
		prefix: 'camellia-128-',
		keylen: 16,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'build',
	},
	{
		token: 'cm192',
		prefix: 'camellia-192-',
		keylen: 24,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'build',
	},
	{
		token: 'cm256',
		prefix: 'camellia-256-',
		keylen: 32,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'build',
	},
	{
		token: 'sm4',
		prefix: 'sm4-',
		keylen: 16,
		ivlen: 16,
		block: 128,
		ceiling: Infinity,
		tier: 'niche',
	},
	{
		token: '2des',
		prefix: 'des-ede-',
		keylen: 16,
		ivlen: 8,
		block: 64,
		ceiling: MAX_64BIT_BYTES,
		tier: 'deprecated',
		modes: ['cbc', 'cfb', 'ofb'],
	},
	{
		token: '3des',
		prefix: 'des-ede3-',
		keylen: 24,
		ivlen: 8,
		block: 64,
		ceiling: MAX_64BIT_BYTES,
		tier: 'deprecated',
		modes: ['cbc', 'cfb', 'ofb'],
	},
]

// chacha20 IV length: the spec assumes 12; some OpenSSL builds (observed:
// 3.6) reject 12 and accept 16. Probed once at load so the material math
// matches what this machine will actually encrypt/decrypt with.
function probeChachaIvLen() {
	for (const n of [12, 16]) {
		try {
			crypto.createCipheriv('chacha20', crypto.randomBytes(32), crypto.randomBytes(n))
			return n
		} catch {
			// try next
		}
	}
	return 12
}

const CHACHA = {
	token: 'chacha',
	cipher: 'chacha20',
	mode: 'str',
	keylen: 32,
	ivlen: probeChachaIvLen(),
	block: null,
	ceiling: Infinity,
	tier: 'core',
}

const UNIVERSE = [
	...FAMILIES.flatMap((f) =>
		(f.modes ?? MODES).map((mode) => ({
			token: `${f.token}-${mode}`,
			cipher: `${f.prefix}${mode}`,
			mode,
			keylen: f.keylen,
			ivlen: f.ivlen,
			block: f.block,
			ceiling: f.ceiling,
			tier: f.tier,
		})),
	),
	CHACHA,
]

export { UNIVERSE }

// Availability is dynamic (distro flags, FIPS, OpenSSL deprecations); the
// metadata above is static and must be identical on every device.
export function probeAvailability() {
	return new Set(crypto.getCiphers())
}

export function parseStack(input) {
	return input
		.split(',')
		.map((t) => t.trim())
		.filter((t) => t !== '')
}

const BAD_ORDER_MSG =
	"vault: bad stack order (need at least 1 token from the alphabet, see 'vault list')"

// Validates against the effective alphabet and fails fast. `open: true`
// selects the open-side availability message (the vault may have been locked
// on another machine).
export function validateStack(tokens, available, { open = false } = {}) {
	if (tokens.length < 1) throw new Error(BAD_ORDER_MSG)
	const rows = []
	for (const token of tokens) {
		const row = UNIVERSE.find((r) => r.token === token)
		if (!row) throw new Error(`vault: stack token not in alphabet: ${token}`)
		if (!available.has(row.cipher)) {
			throw new Error(
				open
					? `vault: stack token not available on this machine: ${token}; this vault cannot be opened here (run 'vault list')`
					: `vault: stack token not available on this machine: ${token} (run 'vault list')`,
			)
		}
		rows.push(row)
	}
	return rows
}

// Alphabet-only resolution (used by `check`, where unavailability is a
// per-line warning, not an error — the stack may target another machine).
export function alphabetRows(tokens) {
	if (tokens.length < 1) throw new Error(BAD_ORDER_MSG)
	return tokens.map((token) => {
		const row = UNIVERSE.find((r) => r.token === token)
		if (!row) throw new Error(`vault: stack token not in alphabet: ${token}`)
		return { token, row }
	})
}

// Stack ceiling = min over its tokens. Depth is NOT bounded here: COUNT =
// len(order) may be anything >= 1; an upper bound would bound the attacker's
// depth search.
export function ceilingFor(rows) {
	return rows.reduce((min, r) => Math.min(min, r.ceiling), Infinity)
}

export function hepFloor(count) {
	return Math.max(64, count)
}

const GROUPS = [
	{ tier: 'core', title: 'CORE — present in essentially every Node/OpenSSL build' },
	{ tier: 'build', title: 'BUILD-DEPENDENT — may be absent in FIPS/minimal/distro builds' },
	{ tier: 'niche', title: 'NICHE — regional standard, often excluded from Western builds' },
	{
		tier: 'deprecated',
		title:
			'DEPRECATED — OpenSSL 3.x deprecates 3DES; may not exist in future builds.\n' +
			'Do not use in a new stack unless you accept re-lock risk.',
	},
]

function line(row, available) {
	const block = row.block == null ? '—' : `${row.block}b`
	const maxv = row.ceiling === Infinity ? 'unlimited' : '4 GiB'
	return `  ${row.token.padEnd(10)}${row.mode.padEnd(6)}${block.padEnd(7)}${maxv.padEnd(12)}${available.has(row.cipher) ? 'yes' : 'no'}`
}

export function renderList(available, nSet) {
	const nList = nSet.map((n) => `${n} (2^${Math.log2(n)})`).join(', ')
	const lines = [
		`VAULT ALPHABET — ${UNIVERSE.length} tokens; availability shown for THIS machine`,
		'',
	]
	for (const g of GROUPS) {
		lines.push(g.title)
		if (g.tier === 'core')
			lines.push(
				`  ${'token'.padEnd(10)}${'mode'.padEnd(6)}${'block'.padEnd(7)}${'max-vault'.padEnd(12)}here`,
			)
		const rows = UNIVERSE.filter((r) => r.tier === g.tier).sort((a, b) =>
			a.token < b.token ? -1 : 1,
		)
		for (const r of rows) lines.push(line(r, available))
		lines.push('')
	}
	lines.push(
		`KDF: scrypt r=1 p=1 — machine-verified N on THIS machine: ${nList} ` +
			'(N is operator-typed per vault: lock and open must be run with the same N)',
	)
	return lines.join('\n').replace(/\n$/, '')
}

export function renderCheck(tokens, available) {
	const resolved = alphabetRows(tokens)
	const rows = resolved.map((r) => r.row)
	const lines = []
	for (const { token, row } of resolved) {
		if (!available.has(row.cipher)) lines.push(`  ${token}: NOT AVAILABLE on this machine`)
		else if (row.tier === 'deprecated')
			lines.push(`  ${token}: ok (DEPRECATED — may not exist in future builds)`)
		else lines.push(`  ${token}: ok`)
	}
	const count = rows.length
	lines.push(`layer count: ${count} -> HEP minimum: ${hepFloor(count)} chars`)
	lines.push(
		ceilingFor(rows) === Infinity
			? 'max vault size for this stack: unlimited'
			: 'max vault size for this stack: 4 GiB (64-bit-block tokens present)',
	)
	if (rows.every((r) => r.cipher === rows[0].cipher)) {
		lines.push(
			'tip: all layers use the same algorithm — blind space collapses to 1; randomize across the alphabet',
		)
	}
	return lines.join('\n')
}
