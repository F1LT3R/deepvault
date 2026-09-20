const { Buffer } = globalThis
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { Transform, PassThrough, Writable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { createDeflate, createInflate } from 'node:zlib'
import { deriveMaterials } from './derive.js'
import { createTarStream, createTarReader, resolveEntryPath } from './tar.js'
import { boundedScan } from './scan.js'
import { MAX_64BIT_BYTES } from './mode.js'

export const HEADER_LEN = 24
export const MAGIC = 'VLT1'

// M0 = R1 || deflate(tar) || R2, nothing else (interior noise would corrupt
// the deflate/tar stream, which IS the acceptance oracle). R2 is 16-aligned
// so every block layer sees block-aligned input — no padding exists anywhere
// in the format, and no padding-oracle surface exists.
export function r1Length() {
	return crypto.randomInt(1024, 65535)
}

export function r2Length(r1Len, deflatedLen) {
	// base is 16-aligned and keeps base+padding <= 65535 (padding <= 15)
	const base = 16 * crypto.randomInt(64, 4096)
	return base + ((16 - ((r1Len + deflatedLen) % 16)) % 16)
}

function unauthenticatedCipher(cipher, key, iv) {
	const c = crypto.createCipheriv(cipher, key, iv)
	// Block layers get block-aligned input by construction; padding would be
	// a format surface, and there is none.
	c.setAutoPadding(false)
	return c
}

// Lock: one streaming pass at any depth — O(1) memory in vault size. The
// COUNT materials are derived up front (COUNT scrypts, ~COUNT s).
export async function lockVault({ vaultfile, entries, hep, rows }) {
	const salt = crypto.randomBytes(16)
	const materials = deriveMaterials(hep, salt, rows)
	const header = Buffer.concat([Buffer.from(MAGIC, 'ascii'), Buffer.alloc(4), salt])
	const r1 = crypto.randomBytes(r1Length())
	const stats = { r1Len: r1.length, deflatedLen: 0, r2Len: 0, salt: salt.toString('hex') }

	// M0 = R1 || deflate(tar) || R2: R1 is injected at the front (never
	// compressed); only the tar is deflated; R2 is appended when the deflate
	// stream has fully ended (its length depends on the deflated size).
	// Strict pull-based draining: defl output is read back synchronously
	// (defl.read()) after each write, so order and backpressure are exact.
	const tar = createTarStream(entries)
	const defl = createDeflate({ level: 6 })
	let r1Pushed = false
	const mid = new Transform({
		highWaterMark: 65536,
		transform(c, _e, cb) {
			drainDefl()
			if (!r1Pushed) {
				r1Pushed = true
				this.push(r1)
			}
			defl.write(c)
			drainDefl()
			cb()
		},
		flush(cb) {
			if (!r1Pushed) {
				r1Pushed = true
				this.push(r1)
			}
			defl.end()
			;(async () => {
				for await (const chunk of defl) {
					stats.deflatedLen += chunk.length
					if (!mid.push(chunk)) {
						await new Promise((res) => mid.once('drain', res))
					}
				}
				stats.r2Len = r2Length(r1.length, stats.deflatedLen)
				this.push(crypto.randomBytes(stats.r2Len))
				cb()
			})().catch((e) => cb(e))
		},
	})
	function drainDefl() {
		for (;;) {
			const chunk = defl.read()
			if (chunk === null) return
			stats.deflatedLen += chunk.length
			if (!mid.push(chunk)) return
		}
	}
	defl.on('error', (e) => mid.destroy(e))
	mid.on('close', () => defl.destroy())
	const ciphers = rows.map((row, i) =>
		unauthenticatedCipher(row.cipher, materials[i].key, materials[i].iv),
	)

	const tmp = `${vaultfile}.tmp`
	// file = header (plain: magic+salt) || E_CNT. The header is written first,
	// outside the cascade; the cipher chain consumes M0 = R1||deflate(tar)||R2.
	const ws = fs.createWriteStream(tmp)
	let headerWritten = false
	const dest = new Writable({
		write(chunk, enc, cb) {
			const proceed = (c) => {
				if (!ws.write(c, enc)) ws.once('drain', () => cb())
				else cb()
			}
			if (headerWritten) proceed(chunk)
			else {
				headerWritten = true
				if (!ws.write(header)) ws.once('drain', () => proceed(chunk))
				else proceed(chunk)
			}
		},
		final(cb) {
			ws.end(cb)
		},
	})
	ws.on('error', (e) => dest.destroy(e))
	try {
		await pipeline(tar, mid, ...ciphers, dest)
	} catch (err) {
		await fs.promises.unlink(tmp).catch(() => {})
		throw new Error(`vault: lock failed: ${err.message}`, { cause: err })
	}
	const fd = await fs.promises.open(tmp, 'r')
	try {
		await fd.sync()
	} finally {
		await fd.close()
	}
	await fs.promises.rename(tmp, vaultfile)
	return stats
}

// Open: single pass. Phase A = nothing fully written yet; phase B = >= 1
// file fully written before the failure point. Both wrong-HEP and wrong-depth
// orders land in phase A by design (one security message, invariant 4).
export async function openVault({ vaultfile, outdir, salt, hep, rows }) {
	const materials = deriveMaterials(hep, salt, rows)
	const src = fs.createReadStream(vaultfile, { start: HEADER_LEN, highWaterMark: 65536 })
	const count = rows.length
	// Peel outermost -> innermost: file body is E_CNT.
	const deciphers = []
	for (let i = count - 1; i >= 0; i--) {
		const d = crypto.createDecipheriv(rows[i].cipher, materials[i].key, materials[i].iv)
		d.setAutoPadding(false)
		deciphers.push(d)
	}
	const m0 = new PassThrough({ highWaterMark: 65536 })
	pipeline(src, ...deciphers, m0).catch((e) => m0.destroy(e))

	const scan = boundedScan(m0)
	let rest
	try {
		rest = await scan.run()
	} catch {
		throw { phase: 'A' }
	}

	const infl = createInflate()
	const tarBytes = new PassThrough({ highWaterMark: 65536 })
	pipeline(rest, infl, tarBytes).catch(() => {})

	const reader = createTarReader(tarBytes)
	let filesWritten = 0
	let outdirCreated = false
	const dirMtimes = []
	const ensureOutdir = async () => {
		if (!outdirCreated) {
			await fs.promises.mkdir(outdir)
			outdirCreated = true
		}
	}

	try {
		for await (const entry of reader) {
			await ensureOutdir()
			const abs = resolveEntryPath(outdir, entry.rel)
			if (entry.type === 'dir') {
				await fs.promises.mkdir(abs, { recursive: true })
				dirMtimes.push({ abs, mtimeSec: entry.mtimeSec })
			} else {
				await fs.promises.mkdir(path.dirname(abs), { recursive: true })
				await pipeline(entry.dataStream, fs.createWriteStream(abs))
				await fs.promises.utimes(abs, entry.mtimeSec, entry.mtimeSec)
				filesWritten++
			}
		}
		await ensureOutdir()
		// Re-apply dir mtimes after all writes: creating files inside a dir
		// bumps its mtime, so the first-pass utimes (if any) would be stale.
		for (const { abs, mtimeSec } of dirMtimes) {
			await fs.promises.utimes(abs, mtimeSec, mtimeSec)
		}
	} catch {
		if (filesWritten === 0) throw { phase: 'A' }
		throw { phase: 'B', filesWritten }
	}
	return filesWritten
}

export function ceilingError(totalBytes, rows) {
	const ceiling = rows.reduce((min, r) => Math.min(min, r.ceiling), Infinity)
	if (totalBytes <= ceiling) return null
	const offenders = [...new Set(rows.filter((r) => r.ceiling !== Infinity).map((r) => r.token))]
	return `vault: vault size ${(totalBytes / 2 ** 30).toFixed(2)} GiB exceeds ${(ceiling / 2 ** 30).toFixed(0)} GiB ceiling for this stack (64-bit-block tokens: ${offenders.join(', ')}); re-lock with a 128-bit/stream-only stack`
}

export { MAX_64BIT_BYTES }
