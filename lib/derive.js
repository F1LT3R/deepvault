const { Buffer } = globalThis
import crypto from 'node:crypto'

// Sections, never a master: layer keys derive from contiguous slices of the
// full HEP. A fixed-length master projection would cap the attacker's search
// at 2^(8*masterlen) regardless of HEP length — with sections the wall is the
// full HEP space. This is a load-bearing invariant; do not "simplify" it.

// scrypt N. The spec targets 2^20 (~1 s, ~512 MiB scratch per layer). Some
// modern OpenSSL builds (e.g. 3.6) hard-cap N at 2^15 and reject larger
// values; the effective N is probed once per process, starting at the spec
// value and stepping down. N is public mechanics (it lives in this file), so
// the effective N on the locking machine must match the opening machine's —
// `vault list` prints it so the operator can check across devices.
const N_CANDIDATES = [1048576, 524288, 262144, 131072, 65536, 32768]
const MAXMEM = 2147483646
let probedN = 0

export function scryptN() {
	if (probedN) return probedN
	for (const n of N_CANDIDATES) {
		try {
			crypto.scryptSync(Buffer.from('probe'), Buffer.alloc(20), 32, {
				N: n,
				r: 1,
				p: 1,
				maxmem: MAXMEM,
			})
			probedN = n
			break
		} catch {
			// try a lower N
		}
	}
	if (!probedN) throw new Error('vault: no usable scrypt N on this machine')
	return probedN
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
// must work.
export function deriveMaterials(hep, salt, rows) {
	const N = scryptN()
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
