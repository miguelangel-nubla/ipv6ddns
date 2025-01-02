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
)

type IPv4Handler struct {
	*ipv6disc.AddrCollection
	Interval time.Duration `json:"interval"`
	Command  string        `json:"command"`
	Args     []string      `json:"args"`
	running  bool
	ticker   *time.Ticker
}

func (h *IPv4Handler) PrettyPrint(prefix string) string {
	var result strings.Builder
	fmt.Fprintf(&result, prefix+"IPv4 (%v): %s", h.Interval, h.Command)
	for _, arg := range h.Args {
		fmt.Fprintf(&result, " %q", arg)
	}
	fmt.Fprintln(&result)
	return result.String()
}

func (h *IPv4Handler) UnmarshalJSON(b []byte) error {
	type Alias IPv4Handler
	aux := &struct {
		Interval interface{} `json:"interval"`
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

	h.AddrCollection = ipv6disc.NewAddrCollection()

	return nil
}

func (h *IPv4Handler) Start() {
	if h.running {
		return
	}
	h.ticker = time.NewTicker(h.Interval)
	h.running = true

	go func() {
		h.runCommand()

		for range h.ticker.C {
			h.runCommand()
		}
	}()
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
	output, err := cmd.RunCommandWithTimeout(timeout, h.Command, h.Args...)
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		netipAddr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}

		addr := ipv6disc.NewAddr(net.HardwareAddr{0, 0, 0, 0, 0, 0}, netipAddr, 0, nil)
		h.AddrCollection.Enlist(addr)
	}
}
