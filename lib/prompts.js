// Secrets are typed at the TTY, never echoed, never piped. Raw-mode stdin:
// characters arrive untransformed; we track line state ourselves. A chunk may
// contain several lines (a pty can deliver a piped buffer in one event) — the
// surplus is buffered for later prompts.

const { process } = globalThis

const buf = { partial: '', lines: [] }

function feed(chunk) {
	for (const ch of chunk) {
		const code = ch.codePointAt(0)
		if (code === 13 || code === 10) {
			buf.lines.push(buf.partial)
			buf.partial = ''
		} else if (code === 3) {
			process.stdout.write('\n')
			process.exit(130)
		} else if (code === 127 || code === 8) {
			buf.partial = buf.partial.slice(0, -1)
		} else if (code >= 32) {
			buf.partial += ch
		}
	}
}

export function readSecret(promptText) {
	return new Promise((resolve, reject) => {
		if (!process.stdin.isTTY) {
			reject(new Error('vault: requires an interactive terminal for secret input'))
			return
		}
		process.stdout.write(promptText)
		if (buf.lines.length > 0) {
			process.stdout.write('\n')
			resolve(buf.lines.shift())
			return
		}
		let closed = false
		const cleanup = () => {
			if (closed) return
			closed = true
			process.stdin.removeListener('data', onData)
			process.stdin.setRawMode(false)
			process.stdin.pause()
		}
		const onData = (chunk) => {
			feed(chunk)
			if (buf.lines.length > 0) {
				cleanup()
				process.stdout.write('\n')
				resolve(buf.lines.shift())
			}
		}
		process.stdin.setRawMode(true)
		process.stdin.setEncoding('utf8')
		process.stdin.resume()
		process.stdin.on('data', onData)
	})
}
