package esphome

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"

	"github.com/enbility/zeroconf/v3"
)

// The mDNS service ESPHome devices announce, which Home Assistant's ESPHome integration discovers.
const mdnsService = "_esphomelib._tcp"

// Advertise announces the device by mDNS on its port, at ips on ifaces, until ctx is done: Home
// Assistant offers to add it. It announces itself when it starts, as RFC 6762 has a new service do,
// for Home Assistant, which queries ever less often, to see it at once; and again when Home
// Assistant gives its key, as the announcement says whether it needs one.
func (d *Device) Advertise(ctx context.Context, port int, ips []net.IP, ifaces []net.Interface) error {
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = ip.String()
	}
	changed := d.keyChange()
	server, err := zeroconf.RegisterProxy(d.Name, mdnsService, "local.", port, d.Name, addrs, d.txt(), ifaces)
	if err != nil {
		return fmt.Errorf("mDNS: %w", err)
	}
	defer server.Shutdown()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			changed = d.keyChange()
			server.SetText(d.txt())
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
