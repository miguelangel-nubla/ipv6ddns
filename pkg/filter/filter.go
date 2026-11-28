package filter

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc"
)

// CheckMAC tells whether the MAC is the filter's, in any form net.ParseMAC reads: the configuration
// keeps the canonical one. A filter that is no MAC matches none.
func CheckMAC(mac net.HardwareAddr, filter string) bool {
	if filter == "" {
		return true
	}
	if strings.EqualFold(mac.String(), filter) {
		return true
	}
	want, err := net.ParseMAC(filter)
	return err == nil && bytes.Equal(mac, want)
}

// ParseMACMask reads a VALUE/MASK pair of MACs, as 00:11:22:00:00:00/ff:ff:ff:00:00:00.
func ParseMACMask(s string) (value, mask net.HardwareAddr, err error) {
	v, m, ok := strings.Cut(s, "/")
	if !ok || strings.Contains(m, "/") {
		return nil, nil, errors.New("not VALUE/MASK, as 00:11:22:00:00:00/ff:ff:ff:00:00:00")
	}
	if value, err = net.ParseMAC(v); err != nil {
		return nil, nil, fmt.Errorf("the value %q is not a MAC, as 00:11:22:00:00:00", v)
	}
	if mask, err = net.ParseMAC(m); err != nil {
		return nil, nil, fmt.Errorf("the mask %q is not a MAC, as ff:ff:ff:00:00:00", m)
	}
	if len(value) != len(mask) {
		return nil, nil, fmt.Errorf("the mask is %d bytes and the value %d: they must be the same length", len(mask), len(value))
	}
	return value, mask, nil
}

// CheckMACMask tells whether the MAC matches every VALUE/MASK pair. A pair that doesn't parse
// matches none: the configuration refuses it, and a filter must not take every host for it.
func CheckMACMask(mac net.HardwareAddr, filters []string) bool {
	for _, f := range filters {
		value, mask, err := ParseMACMask(f)
		if err != nil || len(mac) != len(value) {
			return false
		}
		for i := range mac {
			if (mac[i] & mask[i]) != (value[i] & mask[i]) {
				return false
			}
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
		// "!type": the MAC isn't of the type.
		name, negated := strings.CutPrefix(strings.ToLower(f), "!")
		match := false
		switch name {
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
		if match == negated {
			return false
		}
	}
	return true
}

// CheckFamily tells whether the address is of one of the families, 4 and 6. Without families,
// IPv6 only: the filters were written when discovery found IPv6 addresses only, and one that
// names a MAC must not take the private IPv4 addresses of the device to a public DNS.
func CheckFamily(ip netip.Addr, families []int) bool {
	if len(families) == 0 {
		families = []int{6}
	}
	family := 6
	if ip.Unmap().Is4() {
		family = 4
	}
	return slices.Contains(families, family)
}

// The shared address space of carrier-grade NAT, RFC 6598: not reachable from the Internet.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// CheckIPType tells whether the address is of every type the filters name:
//
//   - global: routable on the Internet: not private, link-local or carrier-grade NAT
//   - private: RFC 1918 IPv4, or IPv6 ULA
//   - ula: IPv6 unique local, fc00::/7
//   - cgnat: carrier-grade NAT IPv4, 100.64.0.0/10
//   - link_local: fe80::/10, or 169.254.0.0/16
//   - eui64, random: an IPv6 interface ID from the MAC, or not
//   - temporary: an IPv6 privacy address of the machine ipv6ddns runs on, as its kernel says; a
//     neighbor's is never known so
//
// "!type" is the address not being of the type: "!temporary". A type that isn't one of these
// matches no address, and "!" of it every one: the configuration refuses it before.
func CheckIPType(addr *ipv6disc.Addr, filters []string) bool {
	if len(filters) == 0 {
		return true
	}

	ip := addr.Addr.Unmap()
	is6 := ip.Is6()

	for _, f := range filters {
		// "!type": the address isn't of the type.
		name, negated := strings.CutPrefix(strings.ToLower(f), "!")
		match := false
		switch name {
		case "global":
			match = ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
		case "private":
			match = ip.IsPrivate()
		case "ula":
			match = isULA(ip)
		case "cgnat":
			match = cgnat.Contains(ip)
		case "link_local":
			match = ip.IsLinkLocalUnicast()
		case "eui64":
			match = isEUI64(addr)
		case "random":
			match = is6 && !isEUI64(addr)
		case "temporary":
			match = addr.Temporary()
		}
		if match == negated {
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

// CheckPrefix tells whether the address is in the prefix. An IPv4-mapped address, ::ffff:a.b.c.d,
// is the IPv4 address it holds, as for family and mask: an IPv4 prefix takes it.
func CheckPrefix(ip netip.Addr, prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return true
	}
	ip = ip.WithZone("")
	if prefix.Addr().Is4() {
		ip = ip.Unmap()
	}
	return prefix.Contains(ip)
}

// ParseIPMask reads a VALUE/MASK pair of addresses of one family, as ::1/::ffff:ffff:ffff:ffff or
// 0.0.0.5/0.0.0.255. The mask is an address, not a prefix length.
//
// A part's family is the one it is written in: IPv4 with dots alone, IPv6 with colons. So
// ::ffff:dead:beef and ::ffff:ffff:ffff, the last 48 bits, are IPv6, though their bytes are those
// of an IPv4-mapped address: they are not unmapped, and come back as written.
func ParseIPMask(s string) (value, mask netip.Addr, err error) {
	const hint = "the mask must be an address, as ::ffff:ffff:ffff:ffff or 0.0.0.255, not a prefix length. For a prefix, use ip.prefix, as 2001:db8::/32"
	v, m, ok := strings.Cut(s, "/")
	if !ok || strings.Contains(m, "/") {
		return value, mask, errors.New("not VALUE/MASK, as ::1/::ffff:ffff:ffff:ffff")
	}
	if value, err = netip.ParseAddr(v); err != nil || value.Zone() != "" {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("the value %q is not an address, as ::1", v)
	}
	if mask, err = netip.ParseAddr(m); err != nil || mask.Zone() != "" {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("the mask %q is not an address: %s", m, hint)
	}
	if value.Is4() != mask.Is4() {
		return netip.Addr{}, netip.Addr{}, errors.New("the value and the mask are of different families")
	}
	return value, mask, nil
}

// CheckMask tells whether the address matches every VALUE/MASK pair: within its family, so a pair
// of the other family matches none of its addresses. A pair that doesn't parse matches none
// either: the configuration refuses it, and a filter must not take every address for it.
//
// The address's family is that of its bytes: an IPv4-mapped one, ::ffff:a.b.c.d, is the IPv4
// address it holds, as for family and prefix, and only a pair written in IPv4 matches it. A pair's
// is the one it is written in, as ParseIPMask has it.
func CheckMask(ip netip.Addr, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return false
	}

	for _, f := range filters {
		value, mask, err := ParseIPMask(f)
		if err != nil || value.Is4() != ip.Is4() {
			return false
		}
		// AsSlice: 4 bytes or 16, the same for the three: the address is unmapped, and a pair
		// written in IPv6 is 16 whatever its bytes.
		ipBytes, valueBytes, maskBytes := ip.AsSlice(), value.AsSlice(), mask.AsSlice()
		for i := range ipBytes {
			if (ipBytes[i] & maskBytes[i]) != (valueBytes[i] & maskBytes[i]) {
				return false
			}
		}
	}
	return true
}
