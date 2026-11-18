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
// add it. ips are the addresses to announce; none, every address of the machine.
func (d *Device) Advertise(ctx context.Context, port int, ips []net.IP) error {
	mac := strings.ReplaceAll(d.MAC.String(), ":", "")
	txt := []string{
		"friendly_name=" + d.FriendlyName,
		"version=" + esphomeVersion,
		"mac=" + mac,
		"platform=host",
		"network=ethernet",
		"api_encryption=Noise_NNpsk0_25519_ChaChaPoly_SHA256",
		"project_name=" + d.Project,
		"project_version=" + d.ProjectVersion,
	}
	service, err := mdns.NewMDNSService(d.Name, mdnsService, "local.", d.Name+".local.", port, ips, txt)
	if err != nil {
		return fmt.Errorf("mDNS: %w", err)
	}
	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return fmt.Errorf("mDNS: %w", err)
	}
	<-ctx.Done()
	return server.Shutdown()
}

// MACFromKey returns a MAC for the device, the same for the same key, so that Home Assistant
// knows it again after a restart: locally administered, unicast, from the key's hash.
func MACFromKey(key []byte) net.HardwareAddr {
	sum := sha256.Sum256(append([]byte("ipv6ddns esphome device "), key...))
	mac := net.HardwareAddr(sum[:6])
	mac[0] = mac[0]&^0x01 | 0x02
	return mac
}
