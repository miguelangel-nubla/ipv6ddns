package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func RunCommandWithTimeout(timeout time.Duration, basedir string, command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = basedir

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("command timed out: %v", err)
	} else {
		if err != nil {
			err = fmt.Errorf("command failed: %v", err)
		}
	}

	return output, err
}
