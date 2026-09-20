const { Buffer } = globalThis
import fs from 'node:fs'
import path from 'node:path'
import { Readable, PassThrough } from 'node:stream'

const BLOCK = 512

// ---------------------------------------------------------------------------
// Writer (deterministic minimal USTAR)
// ---------------------------------------------------------------------------

function writeOctal(buf, off, width, value) {
	const s = value.toString(8).padStart(width - 1, '0')
	if (s.length > width - 1) throw new Error(`tar: value ${value} does not fit field of ${width}`)
	buf.write(s, off, 'ascii')
	// remaining bytes stay NUL
}

export function buildHeader({ rel, type, mtimeSec, size }) {
	const name = Buffer.from(rel, 'utf8')
	if (name.length > 100) throw new Error(`vault: tar entry name too long (>100 bytes): ${rel}`)
	const h = Buffer.alloc(BLOCK)
	name.copy(h, 0)
	writeOctal(h, 100, 8, type === 'dir' ? 0o755 : 0o644)
	writeOctal(h, 108, 8, 0)
	writeOctal(h, 116, 8, 0)
	writeOctal(h, 124, 12, size)
	writeOctal(h, 136, 12, mtimeSec)
	h[156] = type === 'dir' ? 0x35 : 0x30
	h.write('ustar\0', 257, 6, 'ascii')
	h.write('00', 263, 2, 'ascii')
	h.fill(0x20, 148, 156)
	let sum = 0
	for (let i = 0; i < BLOCK; i++) sum += h[i]
	h.write(sum.toString(8).padStart(6, '0'), 148, 'ascii')
	h[154] = 0x20
	h[155] = 0
	return h
}

// entries: [{ rel, type: 'dir'|'file', mtimeSec, size, abs }] — already sorted
// (directories precede children). Files are streamed in 64 KiB chunks; O(1)
// memory in vault size. prelude: buffers yielded before the first entry
// (the VLT1 header + R1) — folded in here because this Node's pipeline()
// takes exactly one source.
export function createTarStream(entries, prelude = []) {
	async function* gen() {
		for (const p of prelude) yield p
		for (const e of entries) {
			yield buildHeader(e)
			if (e.type === 'file') {
				const rs = fs.createReadStream(e.abs, { highWaterMark: 65536 })
				yield* rs
				const rem = e.size % BLOCK
				if (rem !== 0) yield Buffer.alloc(BLOCK - rem)
			}
		}
		yield Buffer.alloc(2 * BLOCK)
	}
	return Readable.from(gen(), { objectMode: false })
}

// ---------------------------------------------------------------------------
// Reader (strict — this is the oracle; be harsh)
// ---------------------------------------------------------------------------

export function isZeroBlock(block) {
	for (let i = 0; i < block.length; i++) if (block[i] !== 0) return false
	return true
}

function parseOctalField(h, off, width) {
	let n = 0
	let digits = 0
	for (let i = 0; i < width; i++) {
		const b = h[off + i]
		if (b >= 0x30 && b <= 0x37) {
			n = n * 8 + (b - 0x30)
			digits++
		} else if (b === 0 || (b === 0x20 && digits > 0)) {
			break
		} else {
			throw new Error('tar: bad octal field')
		}
	}
	return n
}

function parseName(h) {
	let k = 0
	while (k < 100 && h[k] !== 0) k++
	if (k === 0 || k >= 100) throw new Error('tar: bad name')
	for (let i = 0; i < k; i++) {
		if (h[i] < 0x20 || h[i] > 0x7e) throw new Error('tar: bad name')
	}
	for (let i = k; i < 100; i++) {
		if (h[i] !== 0) throw new Error('tar: NUL in wrong place')
	}
	return h.subarray(0, k).toString('ascii')
}

function checkPath(rel, seen) {
	if (rel.startsWith('/')) throw new Error('tar: absolute path rejected')
	const parts = rel.split('/')
	for (const p of parts) {
		if (p === '..') throw new Error('tar: path traversal rejected')
		if (p === '') throw new Error('tar: bad path')
	}
	if (seen.has(rel)) throw new Error('tar: duplicate path')
	seen.add(rel)
}

// Pure header validation; throws on any violation.
export function validateHeaderBlock(block) {
	let sum = 0
	for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : block[i]
	const declared = parseOctalField(block, 148, 8)
	if (declared !== sum) throw new Error('tar: bad checksum')
	const rel = parseName(block)
	const typeflag = block[156]
	if (typeflag !== 0x30 && typeflag !== 0x35) throw new Error('tar: bad typeflag')
	const size = parseOctalField(block, 124, 12)
	const mtimeSec = parseOctalField(block, 136, 12)
	if (typeflag === 0x35 && size !== 0) throw new Error('tar: directory with nonzero size')
	return { rel, type: typeflag === 0x35 ? 'dir' : 'file', size, mtimeSec }
}

// Scan-side acceptance: does this inflated prefix start a plausible tar?
// (First block a valid entry header, or the exact empty-tar terminator pair.)
export function looksLikeTarPrefix(out) {
	if (out.length < BLOCK) return false
	if (isZeroBlock(out.subarray(0, BLOCK))) {
		return out.length === 2 * BLOCK && isZeroBlock(out.subarray(BLOCK, 2 * BLOCK))
	}
	try {
		validateHeaderBlock(out.subarray(0, BLOCK))
		return true
	} catch {
		return false
	}
}

// Pull-based strict reader over a Readable of tar bytes. Entries are yielded
// one at a time; a file entry's dataStream must be fully consumed before the
// next entry is requested, which keeps buffering to O(chunk + 512).
export function createTarReader(source) {
	let buf = Buffer.alloc(0)
	let dead = null
	let pending = null
	// 'end' fires once and must settle whatever wait is outstanding (see
	// scan.js makeNext for the full rationale).
	source.once('end', () => {
		dead = 'eof'
		if (pending) {
			const { resolve, onData } = pending
			pending = null
			source.removeListener('data', onData)
			resolve(null)
		}
	})
	source.once('error', (e) => {
		dead = e
		if (pending) {
			const { reject, onData } = pending
			pending = null
			source.removeListener('data', onData)
			reject(e)
		}
	})

	function sourceNext() {
		if (dead === 'eof') return Promise.resolve(null)
		if (dead !== null) return Promise.reject(dead)
		if (pending) return pending.promise
		let resolve
		let reject
		const promise = new Promise((res, rej) => {
			resolve = res
			reject = rej
		})
		const onData = (c) => {
			source.pause()
			source.removeListener('data', onData)
			pending = null
			resolve(c)
		}
		pending = { promise, resolve, reject, onData }
		source.once('data', onData)
		source.resume()
		return promise
	}

	let phase = 'entry'
	let current = null
	const seen = new Set()

	async function fill(minBytes) {
		while (buf.length < minBytes && dead !== 'eof') {
			const c = await sourceNext()
			if (c === null) break
			buf = Buffer.concat([buf, c])
		}
	}

	// Entry data: a single async pump feeds a PassThrough. Backpressure is
	// bounded-buffer polling (wait until < HWM): in this Node a plain
	// Readable's pull is not re-triggered when its buffer drains via 'data'
	// events while the producer is suspended — polling cannot deadlock.
	// Overshoot is at most one HWM (64 KiB).
	function makeDataStream(size) {
		const pass = new PassThrough({ highWaterMark: 65536 })
		;(async () => {
			try {
				while (current.taken < size) {
					let c
					if (buf.length > 0) {
						c = buf
						buf = Buffer.alloc(0)
					} else {
						c = await sourceNext()
					}
					if (c === null) throw new Error('tar: truncated entry data')
					const take = Math.min(c.length, size - current.taken)
					current.taken += take
					const chunk = c.subarray(0, take)
					if (take < c.length) buf = c.subarray(take)
					pass.write(chunk)
					while (pass.readableLength >= 65536) {
						await new Promise((r) => setTimeout(r, 1))
					}
				}
				// USTAR pads file data to the 512 boundary — the padding is
				// part of the stream and must be consumed, not skipped.
				let pad = (512 - (size % 512)) % 512
				while (pad > 0) {
					if (buf.length > 0) {
						const n = Math.min(pad, buf.length)
						buf = buf.subarray(n)
						pad -= n
					} else {
						const c = await sourceNext()
						if (c === null) throw new Error('tar: truncated padding')
						const n = Math.min(pad, c.length)
						buf = c.subarray(n)
						pad -= n
					}
				}
				pass.end()
			} catch (e) {
				pass.destroy(e)
			}
		})()
		return pass
	}

	async function advanceToEntry() {
		for (;;) {
			if (phase === 'entry') {
				if (current) {
					if (current.type === 'file' && current.taken < current.size) {
						throw new Error('tar: entry data not fully consumed')
					}
					current = null
				}
				await fill(BLOCK)
				if (buf.length < BLOCK) throw new Error('tar: truncated')
				const block = buf.subarray(0, BLOCK)
				if (isZeroBlock(block)) {
					buf = buf.subarray(BLOCK)
					phase = 'terminator1'
					continue
				}
				const e = validateHeaderBlock(block)
				checkPath(e.rel, seen)
				buf = buf.subarray(BLOCK)
				if (e.type === 'file') {
					current = {
						rel: e.rel,
						type: 'file',
						mtimeSec: e.mtimeSec,
						size: e.size,
						taken: 0,
					}
					current.dataStream = makeDataStream(e.size)
					return current
				}
				return { rel: e.rel, type: 'dir', mtimeSec: e.mtimeSec }
			}
			if (phase === 'terminator1') {
				await fill(BLOCK)
				if (buf.length < BLOCK) throw new Error('tar: truncated terminator')
				if (!isZeroBlock(buf.subarray(0, BLOCK)))
					throw new Error('tar: data after terminator')
				buf = buf.subarray(BLOCK)
				phase = 'terminator2'
				continue
			}
			if (phase === 'terminator2') {
				const c = await sourceNext()
				if (c !== null) throw new Error('tar: trailing bytes after terminator')
				phase = 'done'
				return null
			}
			return null
		}
	}

	return {
		[Symbol.asyncIterator]() {
			return {
				async next() {
					const value = await advanceToEntry()
					return value === null
						? { value: undefined, done: true }
						: { value, done: false }
				},
				async return() {
					return { value: undefined, done: true }
				},
			}
		},
	}
}

export function resolveEntryPath(outdir, rel) {
	return path.join(outdir, rel)
}
