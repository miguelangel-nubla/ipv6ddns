package ipv6ddns

import (
	"sync"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
)

type Endpoint struct {
	ddns.Service
	hostnamesMutex sync.RWMutex
	hostnames      map[string]*Hostname
}

func NewEndpoint(service ddns.Service) *Endpoint {
	return &Endpoint{
		hostnames: make(map[string]*Hostname),
		Service:   service,
	}
}
