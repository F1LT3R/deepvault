import { test } from 'node:test'
import assert from 'node:assert'
import { spawn, spawnSync, execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const BIN = path.join(root, 'bin', 'vault.js')
const TMP = path.join(root, 'tmp', 'test')

const {
	UNIVERSE,
	parseStack,
	validateStack,
	alphabetRows,
	ceilingFor,
	hepFloor,
	probeAvailability,
	MAX_64BIT_BYTES,
} = await import('../lib/mode.js')
const { splitSections, deriveMaterials, machineMaxN } = await import('../lib/derive.js')
const TEST_N = machineMaxN()
const { r2Length, lockVault, openVault, ceilingError, HEADER_LEN } =
	await import('../lib/cascade.js')
const { walkDir } = await import('../lib/fsutil.js')

fs.rmSync(TMP, { recursive: true, force: true })
fs.mkdirSync(TMP, { recursive: true })

let counter = 0
function fresh(name) {
	const p = path.join(TMP, `${++counter}-${name}`)
	fs.mkdirSync(p, { recursive: true })
	return p
}

// --- helpers ---------------------------------------------------------------

// Drive the CLI through a real pseudo-TTY (test/pty-run.py creates the pty
// and enforces its own hard timeout), piped input = the prompt lines.
const PTY_RUN = path.join(root, 'test', 'pty-run.py')
function runPty(args, input, timeoutMs = 150000) {
	return new Promise((resolve, reject) => {
		const child = spawn(
			'python3',
			[PTY_RUN, String(Math.ceil(timeoutMs / 1000)), process.execPath, BIN, ...args],
			{
				stdio: ['pipe', 'pipe', 'pipe'],
			},
		)
		let stdout = ''
		let stderr = ''
		const timer = setTimeout(() => {
			child.kill('SIGKILL')
			reject(new Error(`pty run timed out: vault ${args.join(' ')}`))
		}, timeoutMs)
		child.stdout.on('data', (d) => (stdout += d))
		child.stderr.on('data', (d) => (stderr += d))
		child.on('close', (code) => {
			clearTimeout(timer)
			resolve({ code, stdout, stderr, all: stdout + stderr })
		})
		child.on('error', (e) => {
			clearTimeout(timer)
			reject(e)
		})
		child.stdin.write(input)
		child.stdin.end()
	})
}

// Plain spawn (no TTY) — for the non-TTY / pre-prompt failure tests.
function runPlain(args, input = '') {
	return new Promise((resolve) => {
		const child = spawn(process.execPath, [BIN, ...args], { stdio: ['pipe', 'pipe', 'pipe'] })
		let stdout = ''
		let stderr = ''
		child.stdout.on('data', (d) => (stdout += d))
		child.stderr.on('data', (d) => (stderr += d))
		child.on('close', (code) => resolve({ code, stdout, stderr, all: stdout + stderr }))
		child.stdin.write(input)
		child.stdin.end()
	})
}

function makeSampleDir(dir, big = 5 * 1024 * 1024) {
	fs.mkdirSync(path.join(dir, 'sub'), { recursive: true })
	fs.mkdirSync(path.join(dir, 'empty'))
	fs.writeFileSync(path.join(dir, 'a.txt'), 'hello world\n')
	fs.writeFileSync(path.join(dir, 'file with spaces.txt'), 'spaces here')
	const bin = Buffer.alloc(big)
	crypto.randomFillSync(bin)
	fs.writeFileSync(path.join(dir, 'sub', 'big.bin'), bin)
}

async function openVaultFails({ vlt, out, hep, rows, n: TEST_N }) {
	try {
		const buf = fs.readFileSync(vlt)
		await openVault({ vaultfile: vlt, outdir: out, salt: buf.subarray(8, 24), hep, rows })
		return { phase: null }
	} catch (e) {
		if (e && typeof e === 'object' && 'phase' in e) return e
		throw e
	}
}

function listEntries(base) {
	const out = []
	for (const d of fs.readdirSync(base, { withFileTypes: true })) {
		const rel = d.name
		out.push({ rel, type: d.isDirectory() ? 'dir' : 'file' })
		if (d.isDirectory()) {
			for (const sub of listEntries(path.join(base, rel)))
				out.push({ rel: `${rel}/${sub.rel}`, type: sub.type })
		}
	}
	return out.sort((a, b) => (a.rel < b.rel ? -1 : 1))
}

// Compare trees: same entries, byte-identical files, mtime preserved for
// files and dirs (openVault re-applies dir mtimes after all child writes).
function compareTrees(a, b, { checkMtime = true } = {}) {
	const ea = listEntries(a)
	const eb = listEntries(b)
	assert.deepStrictEqual(eb, ea, 'entry lists differ')
	for (const e of ea) {
		const pa = path.join(a, e.rel)
		const pb = path.join(b, e.rel)
		if (e.type === 'file') {
			assert.deepStrictEqual(
				fs.readFileSync(pb),
				fs.readFileSync(pa),
				`file differs: ${e.rel}`,
			)
			if (checkMtime) {
				const want = Math.floor(fs.statSync(pa).mtimeMs / 1000) * 1000
				assert.strictEqual(fs.statSync(pb).mtimeMs, want, `mtime differs: ${e.rel}`)
			}
		} else {
			assert.ok(fs.statSync(pb).isDirectory(), `not a dir: ${e.rel}`)
			if (checkMtime) {
				const want = Math.floor(fs.statSync(pa).mtimeMs / 1000) * 1000
				assert.strictEqual(fs.statSync(pb).mtimeMs, want, `dir mtime differs: ${e.rel}`)
			}
		}
	}
}

// --- test 1: round-trip, mixed depths ---------------------------------------

test('1. round-trip at depths 3 / 10 / 16 (dynamic COUNT)', async () => {
	const dir = fresh('rt')
	const src = path.join(dir, 'src')
	makeSampleDir(src)
	const hep = 'R'.repeat(64)
	const stacks = {
		3: ['a256-ctr', 'chacha', 'sm4-cbc'],
		10: [
			'a128-ctr',
			'a128-cbc',
			'a192-ofb',
			'a192-cfb',
			'a256-ctr',
			'a256-cbc',
			'a256-ofb',
			'a256-cfb',
			'a128-ofb',
			'chacha',
		],
		16: [
			'a128-ctr',
			'a192-cbc',
			'a256-ofb',
			'ar128-ctr',
			'ar192-cbc',
			'ar256-ofb',
			'chacha',
			'a128-cfb',
			'a192-ofb',
			'a256-cfb',
			'ar128-cfb',
			'ar192-ofb',
			'ar256-cbc',
			'a128-ofb',
			'a192-ctr',
			'a256-ofb',
		],
	}
	for (const [depth, stack] of Object.entries(stacks)) {
		const vlt = path.join(dir, `v${depth}.vlt`)
		const order = stack.join(',')
		const lock = await runPty(
			['lock', src, vlt],
			`${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`,
		)
		assert.strictEqual(lock.code, 0, `lock ${depth}: ${lock.stderr}`)
		assert.match(lock.stdout, new RegExp(`vault: locked 3 file\\(s\\) into ${vlt}`))
		const out = path.join(dir, `out${depth}`)
		const open = await runPty(['open', vlt, out], `${hep}\n${order}\n${TEST_N}\n`)
		assert.strictEqual(open.code, 0, `open ${depth}: ${open.stderr}`)
		assert.match(open.stdout, new RegExp(`vault: opened 3 file\\(s\\) from ${vlt} into ${out}`))
		compareTrees(src, out)
	}
})

// --- test 2: non-CTR modes end-to-end ---------------------------------------

test('2. non-CTR modes (cbc/ofb/cfb + 3des + camellia + chacha)', async () => {
	const avail = probeAvailability()
	const want = ['a256-cbc', '3des-ofb', 'cm128-cfb', 'chacha']
	const stack = want.filter(
		(t) =>
			UNIVERSE.find((r) => r.token === t) &&
			avail.has(UNIVERSE.find((r) => r.token === t).cipher),
	)
	assert.ok(stack.length >= 3, 'expected most rows available on this machine')
	const dir = fresh('modes')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 1024)
	const hep = 'M'.repeat(64)
	const vlt = path.join(dir, 'v.vlt')
	const order = stack.join(',')
	const lock = await runPty(['lock', src, vlt], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(lock.code, 0, lock.stderr)
	const out = path.join(dir, 'out')
	const open = await runPty(['open', vlt, out], `${hep}\n${order}\n${TEST_N}\n`)
	assert.strictEqual(open.code, 0, open.stderr)
	compareTrees(src, out)
})

// --- test 3: no plaintext leak ----------------------------------------------

test('3. known plaintext absent from vault bytes', async () => {
	const dir = fresh('leak')
	const src = path.join(dir, 'src')
	fs.mkdirSync(src)
	const needle = `PLAINTEXT-${crypto.randomBytes(16).toString('hex')}`
	fs.writeFileSync(path.join(src, 'leak.txt'), needle.repeat(100))
	const hep = 'L'.repeat(64)
	const vlt = path.join(dir, 'v.vlt')
	const order = 'a256-ctr'
	const lock = await runPty(['lock', src, vlt], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(lock.code, 0, lock.stderr)
	const buf = fs.readFileSync(vlt)
	assert.ok(!buf.includes(needle), 'plaintext found in vault file')
})

// --- test 4: wrong HEP, right order ------------------------------------------

test('4. wrong HEP, right order -> phase A', async () => {
	const dir = fresh('wronghep')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 64)
	const hep = 'W'.repeat(64)
	const order = 'a256-ctr,sm4-cbc'
	const vlt = path.join(dir, 'v.vlt')
	let r = await runPty(['lock', src, vlt], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 0, r.stderr)
	const out = path.join(dir, 'out')
	r = await runPty(['open', vlt, out], `${'X'.repeat(64)}\n${order}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: wrong passphrase\/stack or tampered file/)
	assert.ok(!fs.existsSync(out), 'outdir must not be created')
})

// --- test 5: right HEP, wrong order (incl. wrong depth) -----------------------

test('5. right HEP, wrong order/depth -> phase A', async () => {
	const dir = fresh('wrongorder')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 64)
	const hep = 'O'.repeat(64)
	const ten = [
		'a128-ctr',
		'a128-cbc',
		'a192-ofb',
		'a192-cfb',
		'a256-ctr',
		'a256-cbc',
		'a256-ofb',
		'a256-cfb',
		'a128-ofb',
		'chacha',
	]
	const vlt = path.join(dir, 'v.vlt')
	const order10 = ten.join(',')
	let r = await runPty(['lock', src, vlt], `${order10}\n${order10}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 0, r.stderr)
	// 9-token order against a 10-token vault
	const out9 = path.join(dir, 'out9')
	r = await runPty(['open', vlt, out9], `${hep}\n${ten.slice(0, 9).join(',')}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: wrong passphrase\/stack or tampered file/)
	assert.ok(!fs.existsSync(out9))
	// 11-token order against a 10-token vault
	const out11 = path.join(dir, 'out11')
	r = await runPty(['open', vlt, out11], `${hep}\n${[...ten, 'sm4-cbc'].join(',')}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: wrong passphrase\/stack or tampered file/)
	assert.ok(!fs.existsSync(out11))
})

// --- test 6: HEP floor (dynamic) ---------------------------------------------

test('6. HEP floor: max(64, COUNT) chars', async () => {
	const dir = fresh('floor')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 32)
	const ten = [
		'a128-ctr',
		'a128-cbc',
		'a192-ofb',
		'a192-cfb',
		'a256-ctr',
		'a256-cbc',
		'a256-ofb',
		'a256-cfb',
		'a128-ofb',
		'chacha',
	]
	const order10 = ten.join(',')
	// (a) 63 chars, 10 tokens -> lock fails, no file
	const vlt = path.join(dir, 'v.vlt')
	let r = await runPty(
		['lock', src, vlt],
		`${order10}\n${order10}\n${'f'.repeat(63)}\n${'f'.repeat(63)}\n`,
	)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: passphrase too short \(63 chars; minimum 64 chars\)/)
	assert.ok(!fs.existsSync(vlt))
	// (b) 63 chars, 10 tokens -> open fails, no outdir
	const src2 = path.join(dir, 'src2')
	makeSampleDir(src2, 1024 * 32)
	const hep64 = 'g'.repeat(64)
	r = await runPty(
		['lock', src2, path.join(dir, 'v2.vlt')],
		`${order10}\n${order10}\n${hep64}\n${hep64}\n${TEST_N}\n`,
	)
	assert.strictEqual(r.code, 0, r.stderr)
	r = await runPty(
		['open', path.join(dir, 'v2.vlt'), path.join(dir, 'outX')],
		`${'f'.repeat(63)}\n${order10}\n`,
	)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: passphrase too short \(63 chars; minimum 64 chars\)/)
	assert.ok(!fs.existsSync(path.join(dir, 'outX')))
	// (c) 64 chars, 100 tokens -> minimum 100 chars
	const hundred = Array.from({ length: 100 }, (_, i) => ten[i % ten.length])
	const order100 = hundred.join(',')
	const vlt100 = path.join(dir, 'v100.vlt')
	r = await runPty(
		['lock', src2, vlt100],
		`${order100}\n${order100}\n${'h'.repeat(64)}\n${'h'.repeat(64)}\n`,
	)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: passphrase too short \(64 chars; minimum 100 chars\)/)
	assert.ok(!fs.existsSync(vlt100))
	// (d) 100 chars, 100 tokens -> full round-trip
	const hep100 = 'i'.repeat(100)
	r = await runPty(
		['lock', src2, vlt100],
		`${order100}\n${order100}\n${hep100}\n${hep100}\n${TEST_N}\n`,
	)
	assert.strictEqual(r.code, 0, r.stderr)
	const out100 = path.join(dir, 'out100')
	r = await runPty(['open', vlt100, out100], `${hep100}\n${order100}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 0, r.stderr)
	compareTrees(src2, out100)
	// (e) 64 chars, 10 tokens (boundary) -> works
	const vltB = path.join(dir, 'vb.vlt')
	r = await runPty(
		['lock', src2, vltB],
		`${order10}\n${order10}\n${'j'.repeat(64)}\n${'j'.repeat(64)}\n${TEST_N}\n`,
	)
	assert.strictEqual(r.code, 0, r.stderr)
	const outB = path.join(dir, 'outB')
	r = await runPty(['open', vltB, outB], `${'j'.repeat(64)}\n${order10}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 0, r.stderr)
	compareTrees(src2, outB)
})

// --- test 7: depth unobservable from the file --------------------------------

test('7. depth is unobservable: same M0, COUNT=3 vs 8', async () => {
	const m0 = crypto.randomBytes(4096)
	const salt = crypto.randomBytes(16)
	const hep = 'D'.repeat(64)
	const base = [
		'a128-ctr',
		'a192-cbc',
		'a256-ofb',
		'ar128-cfb',
		'a256-ctr',
		'sm4-ofb',
		'cm128-cbc',
		'chacha',
	]
	const avail = probeAvailability()
	const rowsAll = validateStack(base, avail)
	function cascade(rows, mats) {
		let data = m0
		for (let i = 0; i < rows.length; i++) {
			const c = crypto.createCipheriv(rows[i].cipher, mats[i].key, mats[i].iv)
			c.setAutoPadding(false)
			data = Buffer.concat([c.update(data), c.final()])
		}
		return data
	}
	const rows3 = rowsAll.slice(0, 3)
	const rows8 = rowsAll.slice(0, 8)
	const file3 = Buffer.concat([
		Buffer.from('VLT1'),
		Buffer.alloc(4),
		salt,
		cascade(rows3, deriveMaterials(hep, salt, rows3)),
	])
	const file8 = Buffer.concat([
		Buffer.from('VLT1'),
		Buffer.alloc(4),
		salt,
		cascade(rows8, deriveMaterials(hep, salt, rows8)),
	])
	assert.strictEqual(file3.length, 24 + m0.length)
	assert.strictEqual(file8.length, 24 + m0.length)
	assert.strictEqual(file3.length, file8.length)
	assert.ok(
		file3.subarray(0, 24).equals(file8.subarray(0, 24)),
		'headers (magic+salt) identical — no depth byte',
	)
})

// --- test 8: LE32 index + 300-token round-trip --------------------------------

test('8. LE32 layer index; 300-token stack round-trips', async () => {
	const hep = 'a'.repeat(300)
	const salt = crypto.randomBytes(16)
	const rows = validateStack(
		Array.from({ length: 300 }, (_, i) => ['a128-ctr', 'a256-cbc', 'sm4-ofb'][i % 3]),
		probeAvailability(),
	)
	const N = machineMaxN()
	const mats = deriveMaterials(hep, salt, rows, N)
	const le32 = (n) => {
		const b = Buffer.alloc(4)
		b.writeUInt32LE(n, 0)
		return b
	}
	// layers 255, 256, 257 (1-based 256, 257, 258) derive from salt||LE32
	for (const i of [255, 256, 257]) {
		const row = rows[i]
		const expected = crypto.scryptSync(
			Buffer.from(hep.slice(i, i + 1), 'utf8'),
			Buffer.concat([salt, le32(i + 1)]),
			row.keylen + row.ivlen,
			{ N, r: 1, p: 1, maxmem: 2147483646 },
		)
		assert.ok(
			mats[i].key.equals(expected.subarray(0, row.keylen)),
			`layer ${i + 1} key mismatch`,
		)
		assert.ok(mats[i].iv.equals(expected.subarray(row.keylen)), `layer ${i + 1} iv mismatch`)
	}
	// 300-token round-trip through the CLI
	const dir = fresh('deep300')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 64)
	const vlt = path.join(dir, 'v.vlt')
	const order = rows.map((r) => r.token).join(',')
	let r = await runPty(
		['lock', src, vlt],
		`${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`,
		400000,
	)
	assert.strictEqual(r.code, 0, r.stderr)
	const out = path.join(dir, 'out')
	r = await runPty(['open', vlt, out], `${hep}\n${order}\n${TEST_N}\n`, 400000)
	assert.strictEqual(r.code, 0, r.stderr)
	compareTrees(src, out)
})

// --- test 9: tamper early ------------------------------------------------------

test('9. tamper early (first deflate byte) -> phase A', async () => {
	const dir = fresh('tamper1')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 64)
	const hep = 'T'.repeat(64)
	// Stream-cipher stack: a flipped file byte maps to exactly one M0 byte
	// (a block-cipher inner layer would smear the flip across 16 bytes).
	const rows = validateStack(['a256-ctr', 'sm4-ctr'], probeAvailability())
	const walk = walkDir(src)
	const vlt = path.join(dir, 'v.vlt')
	const stats = await lockVault({ vaultfile: vlt, entries: walk.entries, hep, rows, n: TEST_N })
	const buf = fs.readFileSync(vlt)
	// First byte of the deflate region (the 0x78 zlib header): no valid
	// candidate remains -> phase A, no outdir.
	buf[HEADER_LEN + stats.r1Len] ^= 0xff
	fs.writeFileSync(vlt, buf)
	const out = path.join(dir, 'out')
	const r = await openVaultFails({ vlt, out, hep, rows, n: TEST_N })
	assert.strictEqual(r.phase, 'A')
	assert.ok(!fs.existsSync(out))
})

test('10. tamper 10 bytes before end of deflate -> phase B', async () => {
	const dir = fresh('tamper2')
	const src = path.join(dir, 'src')
	// 3 regular files; the LAST entry (sort order) is compressible so the
	// deflate tail is Huffman-coded — the flip deterministically breaks the
	// stream (a raw stored block would corrupt data silently).
	fs.mkdirSync(path.join(src, 'sub'), { recursive: true })
	fs.writeFileSync(path.join(src, 'a.txt'), 'hello world\n')
	fs.writeFileSync(path.join(src, 'file with spaces.txt'), 'spaces here')
	fs.writeFileSync(path.join(src, 'sub', 'big.bin'), Buffer.alloc(5 * 1024 * 1024, 0x41))
	const hep = 'U'.repeat(64)
	const rows = validateStack(['a256-ctr', 'sm4-cbc'], probeAvailability())
	const walk = walkDir(src)
	const stats = await lockVault({
		vaultfile: path.join(dir, 'v.vlt'),
		entries: walk.entries,
		hep,
		rows,
		n: TEST_N,
	})
	const vlt = path.join(dir, 'v.vlt')
	const flip = HEADER_LEN + stats.r1Len + stats.deflatedLen - 10
	const buf = fs.readFileSync(vlt)
	assert.ok(flip > HEADER_LEN + stats.r1Len, 'flip offset inside the deflate region')
	buf[flip] ^= 0xff
	fs.writeFileSync(vlt, buf)
	let thrown
	try {
		await openVault({
			vaultfile: vlt,
			outdir: path.join(dir, 'out'),
			salt: buf.subarray(8, 24),
			hep,
			rows,
			n: TEST_N,
		})
	} catch (e) {
		thrown = e
	}
	assert.ok(thrown, 'open must fail')
	assert.strictEqual(thrown.phase, 'B', `expected phase B, got ${JSON.stringify(thrown)}`)
	assert.ok(thrown.filesWritten >= 1, 'at least one file fully written')
	const out = path.join(dir, 'out')
	assert.ok(fs.existsSync(out), 'outdir exists in phase B')
	// the fully-written files are byte-identical to the originals
	const names = ['a.txt', 'file with spaces.txt']
	const done = names.filter((n) => fs.existsSync(path.join(out, n)))
	assert.ok(done.length >= 1)
	for (const n of done) {
		assert.deepStrictEqual(
			fs.readFileSync(path.join(out, n)),
			fs.readFileSync(path.join(src, n)),
		)
	}
})

// --- test 11: padding blind spot -----------------------------------------------

test('11. flipping a byte inside R2 is harmless', async () => {
	const dir = fresh('blindspot')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 64)
	const hep = 'V'.repeat(64)
	const rows = validateStack(['a256-ctr', 'sm4-ctr'], probeAvailability())
	const walk = walkDir(src)
	const stats = await lockVault({
		vaultfile: path.join(dir, 'v.vlt'),
		entries: walk.entries,
		hep,
		rows,
		n: TEST_N,
	})
	const vlt = path.join(dir, 'v.vlt')
	// Stream-cipher-only stack: with a block-cipher layer one flipped byte
	// smears across a 16-byte M0 region and can reach the ADLER-32 tail (25%
	// of alignments) — the R2 blind spot is exact for stream ciphers.
	const r2start = HEADER_LEN + stats.r1Len + stats.deflatedLen
	const buf = fs.readFileSync(vlt)
	assert.ok(r2start + 4 < buf.length, 'R2 region exists')
	buf[r2start + 4] ^= 0xff
	fs.writeFileSync(vlt, buf)
	const n = await openVault({
		vaultfile: vlt,
		outdir: path.join(dir, 'out'),
		salt: buf.subarray(8, 24),
		hep,
		rows,
		n: TEST_N,
	})
	assert.strictEqual(n, 3)
	compareTrees(src, path.join(dir, 'out'))
})

// --- test 12: refuse overwrite ---------------------------------------------------

test('12. refuses to overwrite an existing vault file', async () => {
	const dir = fresh('overwrite')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 16)
	const vlt = path.join(dir, 'v.vlt')
	const original = crypto.randomBytes(1234)
	fs.writeFileSync(vlt, original)
	const mtimeBefore = fs.statSync(vlt).mtimeMs
	const hep = 'Z'.repeat(64)
	const order = 'a256-ctr'
	const r = await runPty(['lock', src, vlt], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, new RegExp(`vault: ${vlt} already exists; refusing to overwrite`))
	assert.deepStrictEqual(fs.readFileSync(vlt), original, 'bytes unchanged')
	assert.strictEqual(fs.statSync(vlt).mtimeMs, mtimeBefore, 'mtime unchanged')
})

// --- test 13: symlink rejection ---------------------------------------------------

test('13. symlinks rejected, one line each', async () => {
	const dir = fresh('symlinks')
	const src = path.join(dir, 'src')
	fs.mkdirSync(src)
	fs.writeFileSync(path.join(src, 'real.txt'), 'x')
	fs.symlinkSync(path.join(src, 'real.txt'), path.join(src, 'link1'))
	fs.symlinkSync('/etc/hosts', path.join(src, 'link2'))
	const vlt = path.join(dir, 'v.vlt')
	const hep = 'Y'.repeat(64)
	const order = 'a256-ctr'
	const r = await runPty(['lock', src, vlt], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 1)
	const lines = r.all
		.split('\n')
		.map((l) => l.replace(/\r$/, ''))
		.filter((l) => l.startsWith('vault: symlink not allowed:'))
	assert.deepStrictEqual(lines.sort(), [
		'vault: symlink not allowed: link1',
		'vault: symlink not allowed: link2',
	])
	assert.ok(!fs.existsSync(vlt), 'no vault file created')
})

// --- test 14: no secrets in artifacts ---------------------------------------------

test('14. HEP and stack order absent from file bytes and output', async () => {
	const dir = fresh('nosecrets')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 32)
	const hep = ('SECRET-HEP-' + crypto.randomBytes(40).toString('hex') + '0'.repeat(64)).slice(
		0,
		64,
	)
	assert.strictEqual(hep.length, 64)
	const order = 'ar256-cfb,cm192-ctr'
	const vlt = path.join(dir, 'v.vlt')
	const lock = await runPty(['lock', src, vlt], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(lock.code, 0, lock.stderr)
	const out = path.join(dir, 'out')
	const open = await runPty(['open', vlt, out], `${hep}\n${order}\n${TEST_N}\n`)
	assert.strictEqual(open.code, 0, open.stderr)
	const file = fs.readFileSync(vlt)
	assert.ok(!file.includes(hep), 'HEP in file')
	assert.ok(!file.includes(Buffer.from(order)), 'order in file')
	for (const r of [lock, open]) {
		assert.ok(!r.all.includes(hep), 'HEP in output')
		assert.ok(!r.all.includes(order), 'order in output')
	}
})

// --- test 15: zero runtime deps ----------------------------------------------------

test('15. zero runtime dependencies', () => {
	const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
	assert.ok(
		!pkg.dependencies || Object.keys(pkg.dependencies).length === 0,
		'no runtime dependencies',
	)
	assert.deepStrictEqual(pkg.devDependencies, {
		'@eslint/js': '^10.0.1',
		eslint: '^10.9.1',
		prettier: '^3.9.6',
	})
})

// --- test 16: format determinism ----------------------------------------------------

test('16. same dir+HEP+order -> different bytes, both open', async () => {
	const dir = fresh('determinism')
	const src = path.join(dir, 'src')
	makeSampleDir(src, 1024 * 32)
	const hep = 'K'.repeat(64)
	const order = 'a256-ctr,sm4-cbc'
	const v1 = path.join(dir, '1.vlt')
	const v2 = path.join(dir, '2.vlt')
	let r = await runPty(['lock', src, v1], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 0, r.stderr)
	r = await runPty(['lock', src, v2], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(r.code, 0, r.stderr)
	assert.ok(
		!fs.readFileSync(v1).equals(fs.readFileSync(v2)),
		'files must differ (random salt/R1/R2)',
	)
	for (const [v, o] of [
		[v1, 'o1'],
		[v2, 'o2'],
	]) {
		r = await runPty(['open', v, path.join(dir, o)], `${hep}\n${order}\n${TEST_N}\n`)
		assert.strictEqual(r.code, 0, r.stderr)
		compareTrees(src, path.join(dir, o))
	}
})

// --- test 17: section split (unit) ----------------------------------------------------

test('17. section split and material derivation', () => {
	const cases = [
		[64, 10],
		[65, 10],
		[100, 7],
		[1024, 32],
	]
	const avail = probeAvailability()
	const rows = validateStack(['a256-ctr', 'sm4-cbc', 'chacha'], avail)
	for (const [L, C] of cases) {
		const hep = crypto
			.randomBytes(Math.ceil(L / 2))
			.toString('latin1')
			.slice(0, L)
		const slices = splitSections(hep, C)
		assert.strictEqual(slices.join(''), hep, `concat(slices) === HEP for ${L}/${C}`)
		assert.ok(
			slices.every((s) => s.length > 0),
			'no empty slices',
		)
	}
	// L=64, COUNT=10 -> 6,6,7,6,7,6,6,7,6,7
	assert.deepStrictEqual(
		splitSections('a'.repeat(64), 10).map((s) => s.length),
		[6, 6, 7, 6, 7, 6, 6, 7, 6, 7],
	)
	// materials deterministic for fixed (HEP, salt, N); different HEP -> different materials
	const salt = crypto.randomBytes(16)
	const N = machineMaxN()
	const m1 = deriveMaterials('x'.repeat(64), salt, rows, N)
	const m2 = deriveMaterials('x'.repeat(64), salt, rows, N)
	for (let i = 0; i < rows.length; i++) {
		assert.ok(m1[i].key.equals(m2[i].key) && m1[i].iv.equals(m2[i].iv), 'deterministic')
	}
	const m3 = deriveMaterials('y'.repeat(64), salt, rows, N)
	assert.ok(!m1[0].key.equals(m3[0].key), 'different HEP -> different material')
	// key = material[0:keylen), iv = material[keylen:); salt = salt || LE32(i+1)
	for (let i = 0; i < rows.length; i++) {
		const row = rows[i]
		const expected = crypto.scryptSync(
			Buffer.from(
				'x'.repeat(64).slice(Math.floor((i * 64) / 3), Math.floor(((i + 1) * 64) / 3)),
				'utf8',
			),
			Buffer.concat([
				salt,
				(() => {
					const b = Buffer.alloc(4)
					b.writeUInt32LE(i + 1, 0)
					return b
				})(),
			]),
			row.keylen + row.ivlen,
			{ N, r: 1, p: 1, maxmem: 2147483646 },
		)
		assert.strictEqual(m1[i].key.length, row.keylen)
		assert.strictEqual(m1[i].iv.length, row.ivlen)
		assert.ok(
			m1[i].key.equals(expected.subarray(0, row.keylen)),
			`layer ${i + 1} key = material[0:keylen)`,
		)
		assert.ok(
			m1[i].iv.equals(expected.subarray(row.keylen)),
			`layer ${i + 1} iv = material[keylen:)`,
		)
	}
})

// --- test 18: list output ------------------------------------------------------------

test('18. list prints all 47 tokens with correct availability', () => {
	const out = execFileSync(process.execPath, [BIN, 'list'], { encoding: 'utf8' })
	assert.match(out, /^VAULT ALPHABET — 47 tokens; availability shown for THIS machine/)
	const avail = probeAvailability()
	for (const row of UNIVERSE) {
		const want = avail.has(row.cipher) ? 'yes' : 'no'
		const re = new RegExp(
			`^  ${row.token.padEnd(10)}\\S+ +\\S+ +(unlimited|4 GiB) +${want}$`,
			'm',
		)
		assert.ok(re.test(out), `missing/wrong line for ${row.token} (want here=${want})`)
	}
	assert.strictEqual(UNIVERSE.length, 47)
	assert.match(out, /KDF: scrypt r=1 p=1 — machine-verified N on THIS machine:/)
})

// --- test 19: check behavior -----------------------------------------------------------

test('19. check: per-token lines, ceiling line, tip, invalid token', async () => {
	let r = await runPty(['check'], 'a256-ctr,sm4-cbc\n')
	assert.strictEqual(r.code, 0)
	assert.match(r.stdout, /a256-ctr: ok/)
	assert.match(r.stdout, /sm4-cbc: ok/)
	assert.match(r.stdout, /layer count: 2 -> HEP minimum: 64 chars/)
	assert.match(r.stdout, /max vault size for this stack: unlimited/)
	assert.ok(!r.stdout.includes('tip:'), 'no tip for mixed stack')
	r = await runPty(['check'], '3des-cbc,a256-ctr\n')
	assert.match(r.stdout, /3des-cbc: ok \(DEPRECATED — may not exist in future builds\)/)
	assert.match(r.stdout, /max vault size for this stack: 4 GiB \(64-bit-block tokens present\)/)
	r = await runPty(['check'], 'a256-cbc,a256-cbc\n')
	assert.match(
		r.stdout,
		/tip: all layers use the same algorithm — blind space collapses to 1; randomize across the alphabet/,
	)
	r = await runPty(['check'], 'zz-cbc\n')
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: stack token not in alphabet: zz-cbc/)
})

// --- test 20: availability validation (injected set) -------------------------------------

test('20. validateStack against injected availability sets', () => {
	const tokens = ['a128-ctr', 'sm4-cbc', 'chacha']
	assert.throws(
		() => validateStack(tokens, new Set()),
		/stack token not available on this machine: a128-ctr/,
	)
	assert.throws(() => validateStack([], new Set()), /bad stack order/)
	const rows = validateStack(tokens, probeAvailability())
	assert.ok(rows.every((r) => probeAvailability().has(r.cipher)))
})

// --- test 21: ceiling math ---------------------------------------------------------------

test('21. ceiling math and boundary refusal', () => {
	const avail = probeAvailability()
	const rows64 = validateStack(['3des-cbc'], avail)
	const rows128 = validateStack(['a256-ctr', 'sm4-ctr'], avail)
	assert.strictEqual(ceilingFor(rows64), MAX_64BIT_BYTES)
	assert.strictEqual(ceilingFor(rows128), Infinity)
	assert.strictEqual(ceilingError(2 ** 32 - 1, rows64), null)
	assert.strictEqual(ceilingError(2 ** 32, rows64), null)
	assert.match(
		ceilingError(2 ** 32 + 1, rows64),
		/vault size .* GiB exceeds 4 GiB ceiling for this stack \(64-bit-block tokens: 3des-cbc\)/,
	)
	assert.strictEqual(ceilingError(2 ** 32 + 5, rows128), null)
})

// --- test 22: R2 alignment ------------------------------------------------------------------

test('22. R2 alignment formula', () => {
	for (let i = 0; i < 500; i++) {
		const r1 = 1024 + Math.floor(Math.random() * (65535 - 1024))
		const defl = 1 + Math.floor(Math.random() * 10 ** 6)
		const r2 = r2Length(r1, defl)
		assert.strictEqual((r1 + defl + r2) % 16, 0, 'M0 is 16-aligned')
		assert.ok(r2 >= 1024 && r2 <= 65535, `R2 in [1024, 65535]: ${r2}`)
	}
})

// --- test 23: missing vaultfile ----------------------------------------------------------------

test('23. open on nonexistent vaultfile fails before any prompt', async () => {
	const r = await runPlain(['open', 'no-such-file.vlt', 'out'])
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: no-such-file\.vlt does not exist/)
	assert.ok(!r.stdout.includes('Vault passphrase'), 'no prompt emitted')
})

// --- test 24: non-TTY stdin ---------------------------------------------------------------------

test('24. piped stdin is refused for lock and open', async () => {
	const dir = fresh('notty')
	fs.mkdirSync(path.join(dir, 'src'))
	fs.writeFileSync(path.join(dir, 'src', 'a.txt'), 'x')
	const r1 = await runPlain(
		['lock', path.join(dir, 'src'), path.join(dir, 'v.vlt')],
		'a256-ctr\na256-ctr\n' + 'a'.repeat(64) + '\n' + 'a'.repeat(64) + '\n',
	)
	assert.strictEqual(r1.code, 1)
	assert.match(r1.stderr, /vault: requires an interactive terminal for secret input/)
	const src2 = path.join(dir, 'src2')
	fs.mkdirSync(src2)
	fs.writeFileSync(path.join(src2, 'a.txt'), 'x')
	const hep = 'b'.repeat(64)
	const vlt = path.join(dir, 'v.vlt')
	const rows = validateStack(['a256-ctr'], probeAvailability())
	await lockVault({ vaultfile: vlt, entries: walkDir(src2).entries, hep, rows, n: TEST_N })
	const r2 = await runPlain(['open', vlt, path.join(dir, 'out')], hep + '\na256-ctr\n')
	assert.strictEqual(r2.code, 1)
	assert.match(r2.stderr, /vault: requires an interactive terminal for secret input/)
})

// --- test 25: style gate ---------------------------------------------------------------------------

test('26. full alphabet: every available token in one cascade', async () => {
	const avail = probeAvailability()
	const tokens = UNIVERSE.filter((r) => avail.has(r.cipher)).map((r) => r.token)
	if (tokens.length < 2) return // nothing meaningful to cascade
	const dir = fresh('fullstack')
	const src = path.join(dir, 'src')
	fs.mkdirSync(path.join(src, 'deep'), { recursive: true })
	fs.mkdirSync(path.join(src, 'empty'))
	fs.writeFileSync(path.join(src, 'a.txt'), 'hello full stack\n')
	fs.writeFileSync(path.join(src, 'deep', 'leaf.txt'), 'leaf')
	const comp = Buffer.alloc(200 * 1024)
	for (let i = 0; i < comp.length; i++) comp[i] = i % 13
	fs.writeFileSync(path.join(src, 'deep', 'compressible.bin'), comp)
	fs.writeFileSync(path.join(src, 'deep', 'random.bin'), crypto.randomBytes(64 * 1024))
	const hep = 'F'.repeat(Math.max(64, tokens.length))
	const rows = validateStack(tokens, avail)
	const walk = walkDir(src)
	const vlt = path.join(dir, 'full.vlt')
	await lockVault({ vaultfile: vlt, entries: walk.entries, hep, rows, n: TEST_N })
	const out = path.join(dir, 'out')
	const n = await openVault({
		vaultfile: vlt,
		outdir: out,
		salt: fs.readFileSync(vlt).subarray(8, 24),
		hep,
		rows,
		n: TEST_N,
	})
	assert.strictEqual(n, walk.fileCount)
	compareTrees(src, out)
})

test('27. wrong scrypt N at open -> same single phase A message', async () => {
	const dir = fresh('wrongn')
	const src = path.join(dir, 'src')
	fs.mkdirSync(src)
	fs.writeFileSync(path.join(src, 'a.txt'), 'hello\n')
	const hep = 'W'.repeat(64)
	const order = 'a256-ctr'
	const vlt = path.join(dir, 'v.vlt')
	const lock = await runPty(['lock', src, vlt], `${order}\n${order}\n${hep}\n${hep}\n${TEST_N}\n`)
	assert.strictEqual(lock.code, 0, lock.stderr)
	// A valid but different N (half the machine max): the KDF runs, the peel
	// is uniform noise, and the failure is the single phase-A message.
	const r = await runPty(
		['open', vlt, path.join(dir, 'out')],
		`${hep}\n${order}\n${TEST_N >> 1}\n`,
	)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: wrong passphrase\/stack or tampered file/)
	assert.ok(!fs.existsSync(path.join(dir, 'out')))
})

test('28. bad and too-large scrypt N rejected before KDF', async () => {
	const dir = fresh('baddn')
	const src = path.join(dir, 'src')
	fs.mkdirSync(src)
	fs.writeFileSync(path.join(src, 'a.txt'), 'hello\n')
	const hep = 'B'.repeat(64)
	const order = 'a256-ctr'
	let r = await runPty(
		['lock', src, path.join(dir, 'v1.vlt')],
		`${order}\n${order}\n${hep}\n${hep}\n1000\n`,
	)
	assert.strictEqual(r.code, 1)
	assert.match(r.all, /vault: bad scrypt N \(power of 2 required, e\.g\. 32768\)/)
	r = await runPty(
		['lock', src, path.join(dir, 'v2.vlt')],
		`${order}\n${order}\n${hep}\n${hep}\n999999999999\n`,
	)
	assert.strictEqual(r.code, 1)
	assert.match(
		r.all,
		new RegExp(`vault: scrypt N 999999999999 exceeds this machine's max \\(${TEST_N}\\)`),
	)
	assert.ok(!fs.existsSync(path.join(dir, 'v1.vlt')))
	assert.ok(!fs.existsSync(path.join(dir, 'v2.vlt')))
})

test('25. npm run check passes on the finished tree', () => {
	const r = spawnSync('npm', ['run', 'check'], { cwd: root, encoding: 'utf8' })
	assert.strictEqual(r.status, 0, `npm run check failed:\n${r.stdout}\n${r.stderr}`)
})
