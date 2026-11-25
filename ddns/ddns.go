package ddns

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
)

// Service keeps the A and AAAA records of a host name at a DNS provider.
type Service interface {
	// Update makes the records of hostname the addresses: it adds the missing ones and removes
	// the others. The worker runs one Update of a Service at a time, whatever the host name: it
	// can read the records and then change them.
	//
	// It runs when the addresses of the name change, and again after an error: never to check.
	// So it returns nil only once the records are the addresses and the server answers with
	// them: what an Update that failed left half done, the next must finish, even if it finds
	// nothing to change. And it returns: every wait for the provider has a timeout.
	Update(hostname string, addresses *ipv6disc.AddrCollection) error
	// Domain is the fully qualified name of hostname.
	Domain(hostname string) string
}

// TXTWriter is a Service that also keeps the TXT records of a name, as the DNS challenge of ACME
// needs, by which Let's Encrypt checks that the name is yours.
type TXTWriter interface {
	Service
	// SetTXT makes the TXT records of name, a name of the zone as Update takes it, the values:
	// none removes them. Its other records stay. As Update, it returns once the server answers
	// with them.
	SetTXT(name string, values []string) error
	// FullName is the name of the zone that name is, without the final dot, as Domain, but
	// asking the provider for the zone's name if it must: Route 53 learns it from AWS.
	FullName(name string) (string, error)
}

// txtTTL is the TTL of the TXT records SetTXT writes: short, as they are there for minutes.
const txtTTL = 60

// Warner is a Service with warnings to log, about its settings: an SSH host key it didn't
// verify. Warnings returns each once.
type Warner interface {
	Warnings() []string
}

// ProviderFactory makes a Service from the settings of a credential.
type ProviderFactory func(settings json.RawMessage) (Service, error)

var providers = make(map[string]ProviderFactory)

func RegisterProvider(providerName string, factory ProviderFactory) {
	providers[providerName] = factory
}

// The providers whose services are TXTWriters, by name.
var txtProviders = make(map[string]bool)

// RegisterTXT says of a provider that its service is a TXTWriter: its credential can write the
// DNS challenge. A test checks it of each.
func RegisterTXT(providerName string) {
	txtProviders[providerName] = true
}

// WritesTXT tells whether a provider's service is a TXTWriter.
func WritesTXT(providerName string) bool { return txtProviders[providerName] }

// TXTProviders are the providers whose services are TXTWriters, sorted, as an error lists them:
// "cloudflare, duckdns or route53".
func TXTProviders() string {
	names := slices.Sorted(maps.Keys(txtProviders))
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

func NewService(provider string, settings json.RawMessage) (Service, error) {
	factory, ok := providers[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
	service, err := factory(settings)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", provider, err)
	}
	return service, nil
}

// The JSON schema of each provider's settings, schemas/<provider>.json: what decodeSettings checks,
// and what the providers reference is made of.
//
//go:embed schemas/*.json
var settingsSchemas embed.FS

// SettingsSchema returns the JSON schema of a provider's settings.
func SettingsSchema(provider string) ([]byte, error) {
	return settingsSchemas.ReadFile("schemas/" + provider + ".json")
}

// Providers returns the names of the providers, sorted.
func Providers() []string {
	return slices.Sorted(maps.Keys(providers))
}

// decodeSettings checks settings against the provider's JSON schema, and reads them into v.
func decodeSettings(settings json.RawMessage, provider string, v any) error {
	schema, err := SettingsSchema(provider)
	if err != nil {
		return err
	}
	result, err := gojsonschema.Validate(gojsonschema.NewBytesLoader(schema), gojsonschema.NewBytesLoader(settings))
	if err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !result.Valid() {
		var errs []string
		for _, desc := range result.Errors() {
			errs = append(errs, desc.String())
		}
		return errors.New("invalid settings: " + strings.Join(errs, "; "))
	}
	if err := json.Unmarshal(settings, v); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	return nil
}

// recordType is the DNS record type of an address: A or AAAA.
func recordType(addr netip.Addr) string {
	if addr.Unmap().Is4() {
		return "A"
	}
	return "AAAA"
}

// desiredRecords returns the record type of each address the records should have, keyed by the
// address in its canonical text form.
func desiredRecords(addresses *ipv6disc.AddrCollection) map[string]string {
	desired := make(map[string]string)
	for _, addr := range addresses.Get() {
		ip := addr.WithZone("").Unmap()
		desired[ip.String()] = recordType(ip)
	}
	return desired
}

// canonicalIP returns an address read from a provider in the form desiredRecords keys it with,
// so the two compare.
func canonicalIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return addr.WithZone("").Unmap().String(), true
}
