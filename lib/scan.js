const { Buffer } = globalThis
import { Readable } from 'node:stream'
import { inflateSync, createInflate } from 'node:zlib'
import { looksLikeTarPrefix } from './tar.js'

// The open-side oracle. R1 is bounded (<= 65535) so the deflate offset is
// found by trying every d in [0, 65535) against the first 128 KiB of M0.
// A wrong HEP/order makes this region uniform random and the scan finds
// nothing — same single failure message as a wrong HEP (invariant 4).

export const SCAN_WINDOW = 131072
const CAND_WINDOW = 65536
const PARTIAL_MIN = 4096

// One-chunk-at-a-time reader that leaves the stream paused and resumable.
// One-chunk-at-a-time reader that leaves the stream paused and resumable.
// A single pending wait is settled by whichever arrives first: a data chunk,
// 'end', or 'error'. (An 'end' that fires while a chunk is being taken must
// still resolve the *next* wait — tracked via `dead`, since 'end' fires once.)
function makeNext(stream) {
	let dead = null
	let pending = null
	stream.once('end', () => {
		dead = 'eof'
		if (pending) {
			const { resolve, onData } = pending
			pending = null
			stream.removeListener('data', onData)
			resolve(null)
		}
	})
	stream.once('error', (e) => {
		dead = e
		if (pending) {
			const { reject, onData } = pending
			pending = null
			stream.removeListener('data', onData)
			reject(e)
		}
	})
	return function next() {
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
			stream.pause()
			stream.removeListener('data', onData)
			pending = null
			resolve(c)
		}
		pending = { promise, resolve, reject, onData }
		stream.once('data', onData)
		stream.resume()
		return promise
	}
}

// Partial inflate output for a truncated candidate (only the first 512 bytes
// are kept — enough to parse the USTAR header).
function partialInflate(slice) {
	return new Promise((resolve) => {
		const out = []
		let bytes = 0
		const infl = createInflate()
		infl.on('data', (c) => {
			if (bytes < 512) out.push(c.subarray(0, 512 - bytes))
			bytes += c.length
		})
		infl.on('error', () => {})
		infl.end(slice)
		infl.on('close', () => {
			resolve(bytes >= PARTIAL_MIN ? Buffer.concat(out) : null)
		})
	})
}

async function findOffset(window) {
	for (let d = 0; d < window.length; d++) {
		const slice = window.subarray(d, Math.min(d + CAND_WINDOW, window.length))
		let out
		try {
			out = inflateSync(slice)
		} catch {
			out = await partialInflate(slice)
			if (!out) continue
		}
		if (looksLikeTarPrefix(out)) return d
	}
	return -1
}

export function boundedScan(m0) {
	const next = makeNext(m0)
	let ran = false
	return {
		// Consumes the first SCAN_WINDOW bytes of m0, finds d*, and returns a
		// Readable that yields M0 from d* onward (the rest of the window is
		// unshifted back onto m0, or materialized if m0 already ended).
		async run() {
			if (ran) throw new Error('scan: already run')
			ran = true
			const full = Buffer.alloc(SCAN_WINDOW)
			let pos = 0
			let tail = null
			for (;;) {
				const c = await next()
				if (c === null) break
				const n = Math.min(c.length, SCAN_WINDOW - pos)
				c.subarray(0, n).copy(full, pos)
				pos += n
				if (n < c.length) {
					// Chunk crossed the window boundary: keep the overshoot in a
					// variable — unshifting it now is unsafe (the stream may emit
					// 'end' before we finish, and unshift-after-end is lost).
					tail = c.subarray(n)
				}
				if (pos === SCAN_WINDOW) break
			}
			const window = full.subarray(0, pos)
			const d = await findOffset(window)
			if (d < 0) throw new Error('scan: no deflate candidate found')
			const rest = window.subarray(d)
			// If m0 already ended and its buffer is empty, unshift is no longer
			// possible; materialize instead (window subarray + captured tail). The
			// tail is bounded by one source chunk (<= source HWM).
			if (m0.readableEnded && m0.readableLength === 0) {
				return tail ? Readable.from([rest, tail]) : Readable.from([rest])
			}
			if (tail) m0.unshift(tail)
			m0.unshift(rest)
			return m0
		},
	}
}
