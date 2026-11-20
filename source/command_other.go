//go:build !unix

package source

import "os/exec"

// killWithChildren does nothing here: the command alone is killed when its context is done, and
// what it started stays running.
func killWithChildren(*exec.Cmd) {}
