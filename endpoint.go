package ipv6ddns

import (
	"sync"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc"
)

type Endpoint struct {
	hostnamesMutex sync.RWMutex
	hostnames      map[string]*Hostname
	service        ddns.Service
}

func (e *Endpoint) Update(hostname string) (*ipv6disc.AddrCollection, error) {
	e.hostnamesMutex.RLock()
	h := e.hostnames[hostname]
	// just copy it for now
	addrCollection := h.AddrCollection.Copy()
	e.hostnamesMutex.RUnlock()

	return addrCollection, e.service.Update(hostname, addrCollection)
}

func NewEndpoint(service ddns.Service) *Endpoint {
	return &Endpoint{
		hostnames: make(map[string]*Hostname),
		service:   service,
	}
}
