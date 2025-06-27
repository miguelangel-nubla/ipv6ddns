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
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

type IPv4Handler struct {
	*ipv6disc.AddrCollection
	Interval time.Duration `json:"interval"`
	Command  string        `json:"command"`
	Args     []string      `json:"args"`
	Lifetime time.Duration `json:"lifetime"`
	running  bool
	ticker   *time.Ticker
	logger   *zap.SugaredLogger
	basedir  string
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
	type Alias IPv4Handler
	aux := &struct {
		Interval interface{} `json:"interval"`
		Lifetime interface{} `json:"lifetime"`
		*Alias
	}{
		Alias: (*Alias)(h),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.Interval.(type) {
	case float64:
		h.Interval = time.Duration(value) * time.Second
	case string:
		var err error
		h.Interval, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid debounce time")
	}
	switch value := aux.Lifetime.(type) {
	case float64:
		h.Lifetime = time.Duration(value) * time.Second
	case string:
		var err error
		h.Lifetime, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid lifetime")
	}

	h.AddrCollection = ipv6disc.NewAddrCollection()

	return nil
}

func (h *IPv4Handler) Start(baseDir string, sugaredLogger *zap.SugaredLogger) error {
	if h.running {
		return errors.New("already running")
	}

	h.basedir = baseDir
	h.logger = sugaredLogger

	h.ticker = time.NewTicker(h.Interval)
	h.running = true

	go func() {
		h.runCommand()

		for range h.ticker.C {
			h.runCommand()
		}
	}()

	return nil
}

func (h *IPv4Handler) Stop() {
	h.ticker.Stop()
	h.running = false
}

func (h *IPv4Handler) Running() bool {
	return h.running
}

func (h *IPv4Handler) runCommand() {
	timeout := h.Interval - 1*time.Second

	h.logger.Debugf("running command %s %v with timeout %s", h.Command, h.Args, timeout)
	output, err := cmd.RunCommandWithTimeout(timeout, h.basedir, h.Command, h.Args...)
	if err != nil {
		h.logger.Errorf("error running command %s %v: %s", h.Command, h.Args, err)
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		netipAddr, err := netip.ParseAddr(line)
		if err != nil {
			h.logger.Errorf("failed to parse output from command %s %v: %s", h.Command, h.Args, err)
			continue
		} else {
			h.logger.Debugf("parsed IPv4 address: %s", netipAddr)
		}

		addr := ipv6disc.NewAddr(net.HardwareAddr{0, 0, 0, 0, 0, 0}, netipAddr, h.Lifetime, nil)
		h.AddrCollection.Seen(addr)
	}
}
