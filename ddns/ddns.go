package ddns

import (
	"fmt"
)

type ProviderSettings interface{}

type Service interface {
	Update(domain string, hosts []string) error
	PrettyPrint(string) ([]byte, error)
}

type ProviderFactory func(ProviderSettings) Service

var providers = make(map[string]ProviderFactory)

func RegisterProvider(providerName string, factory ProviderFactory) {
	providers[providerName] = factory
}

func NewDDNSService(provider string, config ProviderSettings) (Service, error) {
	factory, ok := providers[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
	return factory(config), nil
}
