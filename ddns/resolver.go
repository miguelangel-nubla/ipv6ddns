package ddns

import (
	"encoding/json"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"github.com/miguelangel-nubla/ipv6disc"
)

// Resolver is a zone that resolvers of the configuration answer: the names' addresses are kept in
// memory, one copy, where every resolver that answers the zone reads them. The resolvers block is
// the resolver; the records here are read by the configuration, which checks them with the
// resolver's.
type Resolver struct {
	Resolver  string            `json:"resolver"`
	Resolvers []string          `json:"resolvers"`
	Zone      string            `json:"zone"`
	Records   []string          `json:"records"`
	TTL       duration.Duration `json:"ttl"`

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
// needs no network, and never fails. None leaves the name without addresses. Each is answered
// with no TTL past when it expires, which the resolver asks the address itself, as it answers.
func (r *Resolver) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	var addrs []resolver.Address
	for _, addr := range addresses.Get() {
		addrs = append(addrs, resolver.Address{Addr: addr.Addr, Expires: addr.GetExpiration})
	}
	r.addresses.SetExpiring(resolver.Name(hostname, r.Zone), addrs)
	return nil
}

func (r *Resolver) Domain(hostname string) string {
	return FQDN(hostname, r.Zone)
}

// Addresses are the names' addresses, for the resolver to answer with.
func (r *Resolver) Addresses() *resolver.Addresses { return r.addresses }
