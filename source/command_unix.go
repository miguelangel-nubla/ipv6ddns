//go:build unix

package source

import (
	"os/exec"
	"syscall"
)

// killWithChildren has cmd run in a process group of its own, killed whole when its context is
// done: what the command started, and didn't move to another group, ends with it.
func killWithChildren(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
