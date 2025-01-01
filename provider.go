package ipv6ddns

import "sync"

type Provider struct {
	endpointsMutex sync.RWMutex
	endpoints      map[string]*Endpoint
}

func NewProvider() *Provider {
	return &Provider{
		endpoints: make(map[string]*Endpoint),
	}
}
