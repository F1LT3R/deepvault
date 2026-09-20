#!/usr/bin/env node
const { process, Buffer } = globalThis
import fs from 'node:fs'
import {
	probeAvailability,
	parseStack,
	validateStack,
	hepFloor,
	renderList,
	renderCheck,
} from '../lib/mode.js'
import { lockVault, openVault, HEADER_LEN, ceilingError } from '../lib/cascade.js'
import { scryptN } from '../lib/derive.js'
import { readSecret } from '../lib/prompts.js'
import { walkDir } from '../lib/fsutil.js'

const STACK_PROMPT = "Stack order (1+ tokens; see 'vault list'): "
const HEP_PROMPT = 'Vault passphrase: '

function fail(msg) {
	process.stderr.write(`${msg}\n`)
	process.exit(1)
}

function requireTty() {
	if (!process.stdin.isTTY) fail('vault: requires an interactive terminal for secret input')
}

function readRows(tokens, available, open = false) {
	try {
		return validateStack(tokens, available, { open })
	} catch (e) {
		fail(e.message)
	}
}

function checkHepFloor(hep, rows) {
	const floor = hepFloor(rows.length)
	if (hep.length < floor)
		fail(`vault: passphrase too short (${hep.length} chars; minimum ${floor} chars)`)
}

async function cmdLock() {
	const [dir, vaultfile] = process.argv.slice(3)
	if (!dir || !vaultfile) fail('vault: usage: vault lock <dir> <vaultfile>')
	let st
	try {
		st = fs.statSync(dir)
	} catch {
		st = null
	}
	if (!st || !st.isDirectory()) fail(`vault: ${dir} is not a directory`)
	if (fs.existsSync(vaultfile)) fail(`vault: ${vaultfile} already exists; refusing to overwrite`)
	requireTty()

	const order1 = await readSecret(STACK_PROMPT)
	const order2 = await readSecret(STACK_PROMPT)
	if (order1 !== order2) fail('vault: stack confirmation failed')
	const rows = readRows(parseStack(order1), probeAvailability())

	const hep1 = await readSecret(HEP_PROMPT)
	const hep2 = await readSecret(HEP_PROMPT)
	if (hep1 !== hep2) fail('vault: passphrase confirmation failed')
	checkHepFloor(hep1, rows)

	let walk
	try {
		walk = walkDir(dir)
	} catch (e) {
		const lines = []
		if (e && Array.isArray(e.symlinks)) {
			for (const s of e.symlinks) lines.push(`vault: symlink not allowed: ${s}`)
		}
		if (e && Array.isArray(e.badTypes)) {
			for (const b of e.badTypes) lines.push(`vault: non-regular entry not allowed: ${b}`)
		}
		if (lines.length > 0) {
			process.stderr.write(`${lines.join('\n')}\n`)
			process.exit(1)
		}
		fail(e && e.message ? e.message : String(e))
	}
	const ceilingMsg = ceilingError(walk.totalBytes, rows)
	if (ceilingMsg) fail(ceilingMsg)

	try {
		await lockVault({ vaultfile, dir, entries: walk.entries, hep: hep1, rows })
	} catch (e) {
		fail(e.message)
	}
	process.stdout.write(`vault: locked ${walk.fileCount} file(s) into ${vaultfile}\n`)
}

async function cmdOpen() {
	const [vaultfile, outdir] = process.argv.slice(3)
	if (!vaultfile || !outdir) fail('vault: usage: vault open <vaultfile> <outdir>')
	if (!fs.existsSync(vaultfile)) fail(`vault: ${vaultfile} does not exist`)
	let head = Buffer.alloc(HEADER_LEN)
	try {
		const fd = fs.openSync(vaultfile, 'r')
		try {
			const n = fs.readSync(fd, head, 0, HEADER_LEN, 0)
			if (n < HEADER_LEN) head = head.subarray(0, n)
		} finally {
			fs.closeSync(fd)
		}
	} catch {
		head = head.subarray(0, 0)
	}
	if (head.length < HEADER_LEN || head.subarray(0, 4).toString('ascii') !== 'VLT1')
		fail('vault: not a vault file')
	const salt = head.subarray(8, HEADER_LEN)
	if (fs.existsSync(outdir)) fail(`vault: ${outdir} exists; refusing`)
	requireTty()

	const hep = await readSecret(HEP_PROMPT)
	const order = await readSecret(STACK_PROMPT)
	const rows = readRows(parseStack(order), probeAvailability(), true)
	checkHepFloor(hep, rows)

	try {
		const n = await openVault({ vaultfile, outdir, salt, hep, rows })
		process.stdout.write(`vault: opened ${n} file(s) from ${vaultfile} into ${outdir}\n`)
	} catch (e) {
		if (e && e.phase === 'A') fail('vault: wrong passphrase/stack or tampered file')
		if (e && e.phase === 'B') {
			fail(
				`vault: integrity failure — ${e.filesWritten} file(s) fully written before the failure point; inspect ${outdir} before deleting`,
			)
		}
		fail(`vault: open failed: ${e && e.message ? e.message : String(e)}`)
	}
}

function cmdList() {
	process.stdout.write(`${renderList(probeAvailability(), scryptN())}\n`)
}

async function cmdCheck() {
	requireTty()
	const order = await readSecret(STACK_PROMPT)
	const tokens = parseStack(order)
	let out
	try {
		out = renderCheck(tokens, probeAvailability())
	} catch (e) {
		fail(e.message)
	}
	process.stdout.write(`${out}\n`)
}

const cmd = process.argv[2]
if (cmd === 'lock') cmdLock().catch((e) => fail(e.message))
else if (cmd === 'open') cmdOpen().catch((e) => fail(e.message))
else if (cmd === 'list') cmdList()
else if (cmd === 'check') cmdCheck().catch((e) => fail(e.message))
else fail('vault: usage: vault <lock|open|list|check>')
