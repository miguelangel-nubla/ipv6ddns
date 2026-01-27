package filter

import (
	"bytes"
	"net"
	"net/netip"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc"
)

func CheckMAC(mac net.HardwareAddr, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.EqualFold(mac.String(), filter)
}

func CheckMACMask(mac net.HardwareAddr, filters []string) bool {
	if len(filters) == 0 {
		return true
	}

	for _, f := range filters {
		parts := strings.Split(f, "/")
		if len(parts) != 2 {
			continue
		}
		targetMAC, err := net.ParseMAC(parts[0])
		if err != nil {
			continue
		}
		maskMAC, err := net.ParseMAC(parts[1])
		if err != nil {
			continue
		}

		if len(mac) != len(targetMAC) || len(mac) != len(maskMAC) {
			return false
		}

		match := true
		for i := range mac {
			if (mac[i] & maskMAC[i]) != (targetMAC[i] & maskMAC[i]) {
				match = false
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func CheckMACType(mac net.HardwareAddr, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	if len(mac) == 0 {
		return false
	}

	// First byte of MAC address
	// Bit 0 (LSB): 0=Unicast, 1=Multicast
	// Bit 1: 0=Universally Administered (Global), 1=Locally Administered (Local)
	b := mac[0]

	for _, f := range filters {
		match := false
		switch strings.ToLower(f) {
		case "local":
			if (b & 0x02) != 0 {
				match = true
			}
		case "global":
			if (b & 0x02) == 0 {
				match = true
			}
		case "multicast":
			if (b & 0x01) != 0 {
				match = true
			}
		case "unicast":
			if (b & 0x01) == 0 {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func CheckIPType(addr *ipv6disc.Addr, filters []string) bool {
	if len(filters) == 0 {
		return true
	}

	ip := addr.Addr

	for _, f := range filters {
		match := false
		switch strings.ToLower(f) {
		case "global":
			if ip.IsGlobalUnicast() && !isULA(ip) {
				match = true
			}
		case "ula":
			if isULA(ip) {
				match = true
			}
		case "link_local":
			if ip.IsLinkLocalUnicast() {
				match = true
			}
		case "eui64":
			if isEUI64(addr) {
				match = true
			}
		case "random":
			if !isEUI64(addr) {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func isULA(ip netip.Addr) bool {
	// netip.Addr.IsPrivate() covers RFC 1918 (IPv4) and RFC 4193 (IPv6 ULA).
	// But it might cover others. Let's be specific for ULA.
	if !ip.Is6() {
		return false
	}
	b := ip.As16()
	return (b[0] & 0xfe) == 0xfc
}

func isEUI64(addr *ipv6disc.Addr) bool {
	mac := addr.Hw
	if len(mac) != 6 {
		return false
	}
	ip := addr.Addr
	if !ip.Is6() {
		return false
	}

	// Calculate EUI-64 Interface ID
	// 1. Take first 3 bytes
	// 2. Insert fffe
	// 3. Take last 3 bytes
	// 4. Flip 7th bit of 1st byte (Universal/Local)
	eui64 := make([]byte, 8)
	copy(eui64[0:3], mac[0:3])
	eui64[3] = 0xff
	eui64[4] = 0xfe
	copy(eui64[5:8], mac[3:6])
	eui64[0] ^= 0x02

	// Check against last 8 bytes of IP
	ipBytes := ip.As16()
	iid := ipBytes[8:]

	return bytes.Equal(iid, eui64)
}

func CheckPrefix(ip netip.Addr, subnet netip.Prefix) bool {
	if !subnet.IsValid() {
		return true
	}
	return subnet.Contains(ip)
}

func CheckSuffix(ip netip.Addr, suffix string) bool {
	if suffix == "" {
		return true
	}
	return strings.HasSuffix(ip.String(), suffix)
}

func CheckMask(ip netip.Addr, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	if !ip.Is6() {
		return false
	}

	ipBytes := ip.As16()

	for _, f := range filters {
		parts := strings.Split(f, "/")
		if len(parts) != 2 {
			continue
		}

		valIP, err := netip.ParseAddr(parts[0])
		if err != nil {
			continue
		}
		maskIP, err := netip.ParseAddr(parts[1])
		if err != nil {
			continue
		}

		valBytes := valIP.As16()
		maskBytes := maskIP.As16()

		match := true
		for i := 0; i < 16; i++ {
			if (ipBytes[i] & maskBytes[i]) != (valBytes[i] & maskBytes[i]) {
				match = false
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func CheckSource(addr *ipv6disc.Addr, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	// For every filter, we must find a matching source.
	for _, f := range filters {
		found := false
		for _, source := range addr.Sources {
			if source == f {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
