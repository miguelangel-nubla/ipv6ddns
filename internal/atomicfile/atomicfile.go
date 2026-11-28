// Package atomicfile writes the files ipv6ddns keeps, whole and on the disk: a power cut, which
// a router has more than most, leaves the file before or the file after, never an empty or a
// half written one, which the next start couldn't read.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write writes data to path with mode, making its folder, of 0700, when there is none. It
// writes a file beside it, syncs it to the disk, renames it over path, and syncs the folder,
// which has the rename. Until the rename, path is as it was; a failure before it leaves it so.
func Write(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Hidden, and of its own name, so that no glob of the folder's files takes one left by a
	// write that was cut, and two writes at once don't share one.
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	// Nothing, after the rename.
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir syncs a folder, for a rename in it to be on the disk too. Where a folder can't be
// synced, as on Windows, the rename is the system's to keep: it is no error.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	d.Close()
}
