package esphome

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/mdns"
)

// The mDNS service ESPHome devices announce, which Home Assistant's ESPHome integration discovers.
const mdnsService = "_esphomelib._tcp"

// Advertise announces the device by mDNS on its port, until ctx is done: Home Assistant offers to
// add it. ips are the addresses to announce; none, every address of the machine. The announcement
// says whether the device needs its key, and follows when Home Assistant gives one.
func (d *Device) Advertise(ctx context.Context, port int, ips []net.IP) error {
	for {
		changed := d.keyChange()
		server, err := d.announce(port, ips)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return server.Shutdown()
		case <-changed:
			server.Shutdown()
		}
	}
}

func (d *Device) announce(port int, ips []net.IP) (*mdns.Server, error) {
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
	service, err := mdns.NewMDNSService(d.Name, mdnsService, "local.", d.Name+".local.", port, ips, txt)
	if err != nil {
		return nil, fmt.Errorf("mDNS: %w", err)
	}
	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return nil, fmt.Errorf("mDNS: %w", err)
	}
	return server, nil
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
