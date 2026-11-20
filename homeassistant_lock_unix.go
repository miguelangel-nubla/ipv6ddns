//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package ipv6ddns

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes the lock that path is, an empty file it makes, for as long as release isn't
// called and the process runs: errLocked, when another holds it, in this process or any other.
// Where the file system has no locks, nothing is held, and nothing is told.
func lockFile(path string) (release func(), err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err != syscall.EINTR {
			break
		}
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		file.Close()
		return nil, errLocked
	}
	return func() { file.Close() }, nil
}
