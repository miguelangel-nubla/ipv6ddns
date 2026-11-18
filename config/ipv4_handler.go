package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/cmd"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

// IPv4Handler runs a command that prints IPv4 addresses, one per line, at every interval. The
// addresses stay for their lifetime after the last run that printed them.
type IPv4Handler struct {
	*ipv6disc.AddrCollection `json:"-"`

	Interval duration.Duration `json:"interval"`
	Command  string            `json:"command"`
	Args     []string          `json:"args"`
	Lifetime duration.Duration `json:"lifetime"`

	running bool
	stop    chan struct{}
	logger  *zap.SugaredLogger
	basedir string
}

func (h *IPv4Handler) PrettyPrint(prefix string) string {
	var result strings.Builder
	fmt.Fprintf(&result, prefix+"IPv4 (%v): %s", h.Interval, h.Command)
	for _, arg := range h.Args {
		fmt.Fprintf(&result, " %q", arg)
	}
	fmt.Fprintf(&result, "\n")
	if h.AddrCollection != nil {
		result.WriteString(h.AddrCollection.PrettyPrint(prefix + "  "))
	}

	return result.String()
}

func (h *IPv4Handler) UnmarshalJSON(b []byte) error {
	type plain IPv4Handler
	var handler plain
	if err := json.Unmarshal(b, &handler); err != nil {
		return err
	}
	if handler.Interval.Duration <= 0 {
		return fmt.Errorf("invalid ipv4 interval %s: it must be positive", handler.Interval)
	}
	if handler.Lifetime.Duration <= 0 {
		return fmt.Errorf("invalid ipv4 lifetime %s: it must be positive", handler.Lifetime)
	}
	*h = IPv4Handler(handler)
	h.AddrCollection = ipv6disc.NewAddrCollection()
	return nil
}

func (h *IPv4Handler) Start(baseDir string, sugaredLogger *zap.SugaredLogger) error {
	if h.running {
		return errors.New("already running")
	}

	h.basedir = baseDir
	h.logger = sugaredLogger
	h.stop = make(chan struct{})
	h.running = true

	go func() {
		ticker := time.NewTicker(h.Interval.Duration)
		defer ticker.Stop()

		for {
			h.runCommand()
			select {
			case <-ticker.C:
			case <-h.stop:
				return
			}
		}
	}()

	return nil
}

func (h *IPv4Handler) Stop() {
	if h.running {
		close(h.stop)
		h.running = false
	}
}

func (h *IPv4Handler) Running() bool {
	return h.running
}

// commandTimeout leaves the command a second less than the interval, so runs don't overlap.
func (h *IPv4Handler) commandTimeout() time.Duration {
	return max(h.Interval.Duration-time.Second, h.Interval.Duration/2)
}

func (h *IPv4Handler) runCommand() {
	timeout := h.commandTimeout()

	h.logger.Debugf("running command %s %v with timeout %s", h.Command, h.Args, timeout)
	output, err := cmd.RunCommandWithTimeout(timeout, h.basedir, h.Command, h.Args...)
	if err != nil {
		h.logger.Errorf("error running command %s %v: %s", h.Command, h.Args, err)
		return
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		netipAddr, err := netip.ParseAddr(line)
		if err != nil {
			h.logger.Errorf("failed to parse output from command %s %v: %s", h.Command, h.Args, err)
			continue
		}
		h.logger.Debugf("parsed IPv4 address: %s", netipAddr)

		addr := ipv6disc.NewAddr(net.HardwareAddr{0, 0, 0, 0, 0, 0}, netipAddr, "ipv4", h.Lifetime.Duration, nil)
		h.AddrCollection.Seen(addr, "ipv4")
	}

	// Forget the addresses gone for longer than their lifetime.
	for _, addr := range h.AddrCollection.Get() {
		if !addr.Valid() {
			h.AddrCollection.Remove(addr)
		}
	}
}
