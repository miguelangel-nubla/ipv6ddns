package ddns

import (
	"encoding/json"
	"net/netip"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"github.com/miguelangel-nubla/ipv6disc"
)

// Resolver is a zone that a resolver of the configuration answers: the names' addresses are kept
// in memory, where the resolver reads them. The resolvers block is the resolver; the records here
// are read by the configuration, which checks them with the resolver's.
type Resolver struct {
	Resolver string            `json:"resolver"`
	Zone     string            `json:"zone"`
	Records  []string          `json:"records"`
	TTL      duration.Duration `json:"ttl"`

	addresses *resolver.Addresses
}

func init() {
	RegisterProvider("resolver", NewResolver)
}

func NewResolver(settings json.RawMessage) (Service, error) {
	var service Resolver
	if err := decodeSettings(settings, "resolver", &service); err != nil {
		return nil, err
	}
	service.addresses = resolver.NewAddresses()
	return &service, nil
}

// Update makes addresses those the resolver answers hostname with, at once and all together: it
// needs no network, and never fails. None leaves the name without addresses.
func (r *Resolver) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	var addrs []netip.Addr
	for _, addr := range addresses.Get() {
		addrs = append(addrs, addr.Addr)
	}
	r.addresses.Set(resolver.Name(hostname, r.Zone), addrs)
	return nil
}

func (r *Resolver) Domain(hostname string) string {
	return FQDN(hostname, r.Zone)
}

// Addresses are the names' addresses, for the resolver to answer with.
func (r *Resolver) Addresses() *resolver.Addresses { return r.addresses }
