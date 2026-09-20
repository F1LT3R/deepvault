#!/usr/bin/env python3
"""pty helper for the vault test suite.

Creates a real pty, spawns the command with the pty slave on stdin/stdout/
stderr, feeds the piped input (the prompt lines) into the pty immediately
(the kernel line discipline buffers it until the child reads), and streams
everything the child prints back out. Exits with the child's exit code.
Hard timeout: kills the child and exits 124.
"""
import os
import pty
import select
import signal
import subprocess
import sys
import threading

def main() -> int:
	if len(sys.argv) < 2:
		return 2
	timeout_s = 120
	if sys.argv[1].isdigit():
		timeout_s = int(sys.argv[1])
		cmd = sys.argv[2:]
	else:
		cmd = sys.argv[1:]
	data = sys.stdin.buffer.read()
	master, slave = pty.openpty()
	# raw slave (no echo, no canonical mode): the pty line discipline must not
	# echo the secrets back into the captured output (the child reconfigures
	# its own raw mode; this only governs input written before it does).
	import termios
	attrs = termios.tcgetattr(slave)
	attrs[3] = attrs[3] & ~termios.ECHO  # lflag: no echo
	attrs[3] = attrs[3] & ~termios.ICANON
	attrs[6][termios.VMIN] = 1
	attrs[6][termios.VTIME] = 0
	termios.tcsetattr(slave, termios.TCSANOW, attrs)
	proc = subprocess.Popen(
		cmd,
		stdin=slave,
		stdout=slave,
		stderr=slave,
		close_fds=True,
		preexec_fn=os.setsid,
	)
	os.close(slave)
	# macOS pty does NOT buffer input for a slave that is not draining: a
	# blocking write of the whole input can stall until the child reads. Pump
	# it from a background thread — each partial write completes as the child
	# consumes; on child death the write fails (EIO) and the thread ends.
	pos = {'w': 0}

	def pump():
		while pos['w'] < len(data):
			try:
				nb = os.write(master, data[pos['w']:])
				pos['w'] += nb
			except OSError:
				break

	pump_thread = threading.Thread(target=pump, daemon=True)
	pump_thread.start()
	deadline_hits = 0

	def _kill(signum, _frame):
		proc.kill()

	signal.signal(signal.SIGALRM, _kill)
	signal.alarm(timeout_s)
	out = sys.stdout.buffer
	while True:
		try:
			r, _, _ = select.select([master], [], [], 0.2)
		except OSError:
			break
		if master in r:
			try:
				chunk = os.read(master, 65536)
			except OSError:
				break
			if not chunk:
				break
			out.write(chunk)
			out.flush()
		else:
			deadline_hits += 1
			if deadline_hits * 0.2 > timeout_s:
				proc.kill()
				break
	status = proc.wait()
	signal.alarm(0)
	if proc.returncode is not None and (
		proc.returncode == -signal.SIGALRM or deadline_hits * 0.2 > timeout_s
	):
		return 124
	if proc.returncode is None or status < 0:
		return 124
	return status if status >= 0 else 124


if __name__ == "__main__":
	sys.exit(main())
