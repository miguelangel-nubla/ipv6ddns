//go:build unix

package source

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
)

// What a command started ends with it at the timeout: it would otherwise stay running, one more
// at every run.
func TestCommandTimeoutKillsItsChildren(t *testing.T) {
	dir := t.TempDir()
	// The child's output is not the command's: only the kill of the group ends it.
	leaving := config.Source{Type: config.SourceCommand, Command: "sh", Args: []string{"-c", "sleep 60 >/dev/null 2>&1 & echo $! > pid; wait"}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := commandFetcher(leaving, dir)(ctx); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v, want a timeout", err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		t.Fatal(err)
	}
	// Killed, it is gone once init has reaped it.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the process %d the command started is still running", pid)
		}
	}
}

// leavesTheGroup makes the test binary, run as a command, TestCommandHelperLeavesTheGroup's.
const leavesTheGroup = "IPV6DDNS_TEST_LEAVES_THE_GROUP"

// Not a test: the command of TestCommandTimeoutDoesNotWaitForWhatLeftTheGroup, which starts a
// process in a session of its own, with the command's output as its own, tells its pid and waits.
func TestCommandHelperLeavesTheGroup(t *testing.T) {
	if os.Getenv(leavesTheGroup) == "" {
		t.Skip("only as the command of another test")
	}
	child := exec.Command("sleep", "60")
	child.Stdout = os.Stdout
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	// Whole at once, for the test that waits for it.
	if err := os.WriteFile("pid.new", []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename("pid.new", "pid"); err != nil {
		t.Fatal(err)
	}
	child.Wait()
}

// What a command started and moved out of its group, as a daemon does, is not killed with it, and
// holds its output open: the source doesn't wait for it, past a second.
func TestCommandTimeoutDoesNotWaitForWhatLeftTheGroup(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv(leavesTheGroup, "1")
	// It is not killed: the test ends it.
	t.Cleanup(func() {
		if content, err := os.ReadFile(filepath.Join(dir, "pid")); err == nil {
			if pid, err := strconv.Atoi(string(content)); err == nil {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})

	daemon := config.Source{Type: config.SourceCommand, Command: binary, Args: []string{"-test.run=^TestCommandHelperLeavesTheGroup$"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := commandFetcher(daemon, dir)(ctx)
		done <- err
	}()
	// The command's time ends once the process is there, with the output: however long the
	// command took to start it.
	var content []byte
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if content, err = os.ReadFile(filepath.Join(dir, "pid")); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("the command ended before it started its process: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the command started no process: %v", err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Errorf("got %v, want a timeout", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the source still waits for the output of a process that outlived its command")
	}
	pid, _ := strconv.Atoi(string(content))
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the process %d that left the group is gone, so nothing held the output: %v", pid, err)
	}
}
