const { Buffer } = globalThis
import fs from 'node:fs'
import path from 'node:path'

// Walks <dir> (its CONTENTS — no entry for <dir> itself). Symlinks are
// rejected up front and reported in bulk; the CLI prints one line per
// symlink. Entries are sorted lexicographically (directories precede their
// children by the prefix property), which makes the tar deterministic.
export function walkDir(base) {
	const baseAbs = path.resolve(base)
	const entries = []
	const symlinks = []
	const badTypes = []

	function statSeconds(p) {
		return Math.floor(fs.statSync(p).mtimeMs / 1000)
	}

	function record(rel, type, abs) {
		const full = Buffer.byteLength(rel, 'utf8')
		if (full > 100) {
			throw new Error(`vault: tar entry name too long (>100 bytes): ${rel}`)
		}
		entries.push({
			rel,
			type,
			abs,
			mtimeSec: statSeconds(abs),
			size: type === 'file' ? fs.statSync(abs).size : 0,
		})
	}

	function walk(dirAbs, relPrefix) {
		const dirents = fs.readdirSync(dirAbs, { withFileTypes: true })
		for (const d of dirents) {
			const rel = relPrefix ? `${relPrefix}/${d.name}` : d.name
			if (d.isSymbolicLink()) {
				symlinks.push(rel)
				continue
			}
			const abs = path.join(dirAbs, d.name)
			if (d.isDirectory()) {
				record(rel, 'dir', abs)
				walk(abs, rel)
			} else if (d.isFile()) {
				record(rel, 'file', abs)
			} else {
				badTypes.push(rel)
			}
		}
	}

	walk(baseAbs, '')
	if (symlinks.length > 0) throw { symlinks }
	if (badTypes.length > 0) {
		throw { badTypes }
	}
	entries.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0))
	const fileCount = entries.filter((e) => e.type === 'file').length
	const totalBytes = entries.reduce((sum, e) => sum + e.size, 0)
	return { entries, fileCount, totalBytes }
}
