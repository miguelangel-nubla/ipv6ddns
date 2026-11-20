"""A terminal for a command, for the live test of -live: a pseudo-terminal of 60 lines by 200
columns, its own, as the terminal a user runs it at. What is written to this script's input is
typed there, and its screen goes to this script's output. It ends as the command does.

    terminal.py <command> [arguments]
"""

import fcntl
import os
import pty
import select
import struct
import sys
import termios

pid, terminal = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 200, 0, 0))
    os.execvp(sys.argv[1], sys.argv[1:])

keys = [0]
while True:
    readable, _, _ = select.select([terminal] + keys, [], [])
    try:
        if terminal in readable:
            os.write(1, os.read(terminal, 65536))
        if 0 in readable:
            typed = os.read(0, 1024)
            if typed:
                os.write(terminal, typed)
            else:
                keys = []
    except OSError:
        # The command ended, and its terminal with it.
        break
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
