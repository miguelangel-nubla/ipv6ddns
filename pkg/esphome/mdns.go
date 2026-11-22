package esphome

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/enbility/zeroconf/v3"
)

// The mDNS service ESPHome devices announce, which Home Assistant's ESPHome integration discovers.
const mdnsService = "_esphomelib._tcp"

// Advertise announces the device by mDNS on its port, on ifaces, until ctx is done: Home Assistant
// offers to add it. On each interface, it gives that interface's addresses only, which those who
// hear it there can reach, and not those of its other networks, as the bridges of a container's.
// It announces itself when it starts, as RFC 6762 has a new service do, for Home Assistant, which
// queries ever less often, to see it at once; and again when Home Assistant gives its key, as the
// announcement says whether it needs one. It registers the service again for that: the library's
// SetText changes the records its goroutines read without a lock.
//
// Before the first announcement it looks, for mdnsLook, for another device announced there with
// its name or its MAC, as a second instance left with the name of the first: it doesn't announce
// itself then, and that is the error. Two that announced one name would be one device to Home
// Assistant, at the port of whichever answered last, gone when either stops.
func (d *Device) Advertise(ctx context.Context, port int, ifaces []net.Interface) error {
	if len(ifaces) == 0 {
		return errors.New("mDNS: no interface to announce on")
	}
	if err := d.taken(ctx, port, ifaces); err != nil {
		return fmt.Errorf("mDNS: %w", err)
	}
	for {
		changed := d.keyChange()
		// No addresses given: the library answers, and announces, on each interface with its own.
		// One server for all: servers sharing the port would each answer every query, on Linux,
		// which gives a socket the multicast of every interface any socket joined the group on.
		server, err := zeroconf.RegisterProxy(d.Name, mdnsService, "local.", port, d.Name, nil, d.txt(), ifaces)
		if err != nil {
			return fmt.Errorf("mDNS: %w", err)
		}
		select {
		case <-ctx.Done():
			server.Shutdown()
			return nil
		case <-changed:
			server.Shutdown()
		}
	}
}

// mdnsLook is how long Advertise looks for another device with the name or the MAC, before it
// announces: the answers come within a second, as RFC 6762 has them.
var mdnsLook = 1500 * time.Millisecond

// taken is the error of another device announced on ifaces with this one's name, or with its MAC:
// one that answers now, so not this one's own announcement of before, which is no more. An answer
// with the same name, MAC and port is that, kept by a reflector of mDNS between networks: none.
func (d *Device) taken(ctx context.Context, port int, ifaces []net.Interface) error {
	ctx, cancel := context.WithTimeout(ctx, mdnsLook)
	defer cancel()
	entries, removed := make(chan *zeroconf.ServiceEntry, 16), make(chan *zeroconf.ServiceEntry, 16)
	done := make(chan error, 1)
	go func() {
		done <- zeroconf.Browse(ctx, mdnsService, "local.", entries, removed, zeroconf.SelectIfaces(ifaces))
	}()
	mac := strings.ReplaceAll(d.MAC.String(), ":", "")
	var taken error
	check := func(entry *zeroconf.ServiceEntry) {
		theirs := ""
		for _, txt := range entry.Text {
			if value, ok := strings.CutPrefix(txt, "mac="); ok {
				theirs = value
			}
		}
		sameName, sameMAC := strings.EqualFold(entry.Instance, d.Name), mac != "" && strings.EqualFold(theirs, mac)
		if taken != nil || !sameName && !sameMAC || sameName && sameMAC && entry.Port == port {
			return
		}
		var at []string
		for _, ip := range slices.Concat(entry.AddrIPv4, entry.AddrIPv6) {
			at = append(at, ip.String())
		}
		what := fmt.Sprintf("the name %s", d.Name)
		if !sameName {
			what = fmt.Sprintf("the MAC of %s, as %s", d.Name, entry.Instance)
		}
		taken = fmt.Errorf("another device already announces %s, at %s, port %d: each device needs its own name, and its own key or state file", what, strings.Join(at, ", "), entry.Port)
		// Found: no more to look for.
		cancel()
	}
	for {
		select {
		case entry, open := <-entries:
			if open {
				check(entry)
			} else {
				entries = nil
			}
		case _, open := <-removed:
			if !open {
				removed = nil
			}
		case err := <-done:
			// The browsing ended, with its time, or couldn't start, without mDNS to look with:
			// the announcement tells then. What it left unread is read.
			if err != nil {
				d.logf("looking for another device of this name: %s", err)
			}
			for {
				select {
				case entry, open := <-entries:
					if open {
						check(entry)
						continue
					}
				default:
				}
				return taken
			}
		}
	}
}

// txt is the announcement's: what Home Assistant reads of a device before connecting to it.
func (d *Device) txt() []string {
	txt := []string{
		"friendly_name=" + d.FriendlyName,
		"version=" + esphomeVersion,
		"mac=" + strings.ReplaceAll(d.MAC.String(), ":", ""),
		"platform=host",
		"network=ethernet",
		"project_name=" + d.Project,
		"project_version=" + d.ProjectVersion,
	}
	// Without it, Home Assistant adds the device without asking for a key, and gives it one.
	if d.HasKey() {
		txt = append(txt, "api_encryption=Noise_NNpsk0_25519_ChaChaPoly_SHA256")
	}
	return txt
}

// MACFrom returns a MAC for the device, the same for the same seed, so that Home Assistant knows
// it again after a restart: locally administered, unicast, from the seed's hash. The seed is its
// key, when fixed, or an identity kept beside the key Home Assistant gives, which changes it.
func MACFrom(seed []byte) net.HardwareAddr {
	sum := sha256.Sum256(append([]byte("ipv6ddns esphome device "), seed...))
	mac := net.HardwareAddr(sum[:6])
	mac[0] = mac[0]&^0x01 | 0x02
	return mac
}
