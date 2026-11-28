//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runToEnd runs the command with the configuration at path until it ends by itself: its exit
// code and what it wrote.
func runToEnd(t *testing.T, path string) (int, string) {
	t.Helper()
	output := &syncBuffer{}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "IPV6DDNS_RUN_COMMAND=1", "IPV6DDNS_COMMAND_ARGS=--config "+path)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), output.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, output.String()
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("the command didn't end:\n%s", output.String())
		return 0, ""
	}
}

// A web server's port that another program holds ends the start before the worker begins: no
// resolver listens, no Home Assistant device is announced, nothing is left to undo; and it ends
// with 1, which a service manager tries again, as the port may be free then.
func TestWebPortTakenStartsNothing(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
listeners:
  web:
    listen:
      - http://%s
  lan:
    listen:
      - dns://127.0.0.1:%s
webservers:
  main:
    listeners:
      - web
log_level: info
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
resolvers:
  lan:
    listeners:
      - lan
    upstream:
      - 127.0.0.1:%s
tasks: {}
discovery:
  ipv6:
    enabled: false
`, taken.Addr(), freePort(t), freePort(t))), 0o600); err != nil {
		t.Fatal(err)
	}
	code, output := runToEnd(t, path)
	if code != 1 || !strings.Contains(output, "webservers.main failed") || !strings.Contains(output, "address already in use") {
		t.Errorf("exit %d, want 1 and the web server's error:\n%s", code, output)
	}
	if strings.Contains(output, "resolver lan listening") {
		t.Errorf("the worker started, the resolver listening, before the web server failed:\n%s", output)
	}
}

// A configuration that can't be used ends the command with exitConfig, which the unit of
// systemd doesn't restart: the same would fail again every 5 seconds.
func TestConfigErrorExitCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("tasks: {}\nno_such_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, output := runToEnd(t, path); code != exitConfig || !strings.Contains(output, "error reading config") {
		t.Errorf("exit %d, want %d and the configuration's error:\n%s", code, exitConfig, output)
	}
	if code, output := runToEnd(t, filepath.Join(t.TempDir(), "none.yaml")); code != exitConfig {
		t.Errorf("no configuration: exit %d, want %d:\n%s", code, exitConfig, output)
	}
}
