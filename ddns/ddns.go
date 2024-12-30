package ddns

import (
	"fmt"

	"github.com/miguelangel-nubla/ipv6disc"
)

type ProviderSettings interface{}

type Service interface {
	Update(hostname string, addresses *ipv6disc.AddrCollection) error
	PrettyPrint(string) ([]byte, error)
	Domain(hostname string) string
}

type ProviderFactory func(ProviderSettings) Service

var providers = make(map[string]ProviderFactory)

func RegisterProvider(providerName string, factory ProviderFactory) {
	providers[providerName] = factory
}

func NewService(provider string, config ProviderSettings) (Service, error) {
	factory, ok := providers[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
	return factory(config), nil
}
