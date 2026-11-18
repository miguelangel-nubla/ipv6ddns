package config

import (
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/schematest"
)

func TestSchemaMatchesConfig(t *testing.T) {
	schematest.Check(t, string(configSchema), Config{})
}
