const { Buffer } = globalThis
import crypto from 'node:crypto'

// Sections, never a master: layer keys derive from contiguous slices of the
// full HEP. A fixed-length master projection would cap the attacker's search
// at 2^(8*masterlen) regardless of HEP length — with sections the wall is the
// full HEP space. This is a load-bearing invariant; do not "simplify" it.

// scrypt N. The spec targets 2^20 (~1 s, ~512 MiB scratch per layer). Some
// modern OpenSSL builds (e.g. 3.6) hard-cap N at 2^15 and reject larger
// values, so this process can only RUN up to a probed maximum.
//
// N is NOT auto-used and is NOT stored in the vault file: the operator types
// it at lock and retypes it at open (third typed secret, like HEP and stack
// order). The probe only validates that a typed N is runnable here and
// advertises the machine max (`vault list` footer). A wrong-but-valid N at
// open derives different keys and falls into the same single phase-A
// message as a wrong HEP/order (invariant 4 — no new oracle).
const N_CANDIDATES = [1048576, 524288, 262144, 131072, 65536, 32768]
const MAXMEM = 2147483646
let probedMaxN = 0

export function machineMaxN() {
	if (probedMaxN) return probedMaxN
	for (const n of N_CANDIDATES) {
		try {
			crypto.scryptSync(Buffer.from('probe'), Buffer.alloc(20), 32, {
				N: n,
				r: 1,
				p: 1,
				maxmem: MAXMEM,
			})
			probedMaxN = n
			break
		} catch {
			// try a lower N
		}
	}
	if (!probedMaxN) throw new Error('vault: no usable scrypt N on this machine')
	return probedMaxN
}

// The machine-verified N set: every candidate actually probed (no early
// break). `vault list` prints this — it is the menu the operator picks from
// when typing N at lock/open.
let verifiedN = null
export function machineNSet() {
	if (verifiedN) return verifiedN
	const ok = []
	for (const n of N_CANDIDATES) {
		try {
			crypto.scryptSync(Buffer.from('probe'), Buffer.alloc(20), 32, {
				N: n,
				r: 1,
				p: 1,
				maxmem: MAXMEM,
			})
			ok.push(n)
		} catch {
			// not runnable here
		}
	}
	if (ok.length === 0) throw new Error('vault: no usable scrypt N on this machine')
	verifiedN = ok.sort((a, b) => a - b)
	return verifiedN
}

// All HEP length/split math is in JS string length (UTF-16 code units).
// L >= COUNT is guaranteed by the caller (prompt-time floor), so no slice is
// empty; concat(slices) === hep exactly.
export function splitSections(hep, count) {
	const L = hep.length
	const slices = []
	for (let i = 0; i < count; i++) {
		const a = Math.floor((i * L) / count)
		const b = Math.floor(((i + 1) * L) / count)
		slices.push(hep.slice(a, b))
	}
	return slices
}

function le32(n) {
	const b = Buffer.alloc(4)
	b.writeUInt32LE(n >>> 0, 0)
	return b
}

// One scrypt per layer, key and IV from one output. Layer index (i+1) is
// folded into the scrypt salt as 4-byte little-endian — counts beyond 255
// must work. N is operator-typed (see the scrypt N note above).
export function deriveMaterials(hep, salt, rows, N) {
	const params = { N, r: 1, p: 1, maxmem: MAXMEM }
	const slices = splitSections(hep, rows.length)
	return slices.map((slice, i) => {
		const row = rows[i]
		const material = crypto.scryptSync(
			Buffer.from(slice, 'utf8'),
			Buffer.concat([salt, le32(i + 1)]),
			row.keylen + row.ivlen,
			params,
		)
		return { key: material.subarray(0, row.keylen), iv: material.subarray(row.keylen) }
	})
}
