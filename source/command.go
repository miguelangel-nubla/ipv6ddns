package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/config"
)

// commandFetcher runs the command, in baseDir, and reads the addresses it prints, one per line.
func commandFetcher(cfg config.Source, baseDir string) fetcher {
	return func(ctx context.Context) ([]netip.Addr, error) {
		cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)
		cmd.Dir = baseDir
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if err != nil {
			if ctx.Err() != nil {
				err = fmt.Errorf("timed out: %w", ctx.Err())
			}
			if message := strings.TrimSpace(stderr.String()); message != "" {
				err = fmt.Errorf("%w: %s", err, message)
			}
			return nil, fmt.Errorf("command %s failed: %w", cfg.Command, err)
		}
		return parseAddresses(string(output))
	}
}

// parseAddresses reads addresses, one per line; blank lines don't count. It returns those it
// read, and an error naming the lines that aren't addresses.
func parseAddresses(output string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	var errs []error
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("not an address: %q", line))
			continue
		}
		addrs = append(addrs, addr.WithZone(""))
	}
	return addrs, errors.Join(errs...)
}
