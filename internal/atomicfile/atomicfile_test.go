package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A file is written whole, in a folder made for it, with its mode; written again, replaced; and
// a write that fails leaves the one before. No file of the writes stays beside it.
func TestWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "deeper")
	path := filepath.Join(dir, "push-wan.json")
	if err := Write(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte(`{"a":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != `{"a":2}` {
		t.Errorf("the file: %q, %v", data, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the mode: %v, %v", info.Mode().Perm(), err)
		}
		if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("the folder's mode: %v, %v", info.Mode().Perm(), err)
		}
	}

	// A folder in place of the file: the rename fails, and the folder stays.
	blocked := filepath.Join(dir, "blocked.json")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "inside"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(blocked, []byte("x"), 0o600); err == nil {
		t.Error("written over a folder")
	}
	if info, err := os.Stat(blocked); err != nil || !info.IsDir() {
		t.Errorf("the folder written over: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "push-wan.json" && e.Name() != "blocked.json" {
			t.Errorf("left beside it: %s", e.Name())
		}
	}
}
