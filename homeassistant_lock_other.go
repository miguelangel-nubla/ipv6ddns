//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package ipv6ddns

// lockFile holds nothing here: the system has no lock that ends with its process.
func lockFile(path string) (release func(), err error) {
	return func() {}, nil
}
