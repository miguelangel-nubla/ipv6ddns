//go:build unix

package ddns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The commands of a local update have updateTimeout together, as over SSH: each with its own,
// an update of several would hold its endpoint for as many. A PowerShell of the test's, pwsh on
// the PATH, takes a second for each command.
func TestWindowsLocalUpdateTimeout(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\n/bin/sleep 1\necho '[]'\n"
	if err := os.WriteFile(filepath.Join(dir, "pwsh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	timeouts(t, httpTimeout, 1500*time.Millisecond)

	// Four commands: the records read, and three added.
	service := &WindowsDNS{Zone: "example.com"}
	took, err := returnsWithin(t, 3500*time.Millisecond, func() error { return service.Update("nas", desired()) })
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("the update, after %s: %v, want it timed out", took.Round(time.Millisecond), err)
	}
}
