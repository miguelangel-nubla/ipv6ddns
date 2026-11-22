package docgen

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6disc"
)

var update = flag.Bool("update", false, "write the pages")

// The pages in the repository are those the schemas make: after changing a schema,
// go test ./internal/docgen -update.
func TestPagesUpToDate(t *testing.T) {
	pages, err := Pages()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range pages {
		path = filepath.Join("..", "..", path)
		if *update {
			if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != want {
			t.Errorf("%s is behind the schemas: go test ./internal/docgen -update", path)
		}
	}
}

// The reference has the discovery as ipv6disc has it: every protocol, with its options and their
// defaults, and what is ipv6ddns's own beside them.
func TestConfigurationHasTheDiscovery(t *testing.T) {
	page, err := Configuration()
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range ipv6disc.ProtocolNames() {
		if !strings.Contains(page, "### "+protocol+"\n\n`discovery.protocols."+protocol+"`\n") {
			t.Errorf("no section of the %s protocol", protocol)
		}
	}
	for _, want := range []string{
		"## Discovery\n\n`discovery`\n",
		"| `lifetime` | duration | `1h` | How long an address stays after it was last seen, unless its family sets its own. |",
		"## Discovery IPv4\n\n`discovery.ipv4`\n",
		"| `enabled` | boolean | `false` | Whether the family's addresses are kept",
		"## Discovery hostnames\n\n`discovery.hostnames`\n",
		"## Discovery solicit\n\n`discovery.solicit`\n",
		"| `ipv6` | boolean | `false` | For each filter with a mac.address and the eui64 type",
		"| `ask` | boolean | `true` | ",
		"| `max_prefix` | number | `22` | ",
		"| `servers` | list, or comma separated | - | ",
		"| `plugins` | object | - | ",
		"## Discovery plugins\n\n`discovery.plugins.<name>`\n",
		"| `interval` | duration | **Required.** How often the table is read, as 60s or 5m. |",
		"| `use_tls` | boolean | ",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the reference has no %q", want)
		}
	}
	for _, gone := range []string{"webserver_listen", "solicit_eui64", "`params`", "flag", "Deprecated, and goes in v1.0: discovery"} {
		if strings.Contains(page, gone) {
			t.Errorf("the reference still has %q", gone)
		}
	}
}

// The descriptions are ipv6disc's, read by the users of both: what is true of one program's image
// only, as ipv6disc's having no CAs, belongs in its documentation, not in them.
func TestPluginFieldDescriptionsAreOfNoImage(t *testing.T) {
	for _, def := range pluginDefs {
		described, err := PluginFieldDescriptions(def.pluginType)
		if err != nil {
			t.Fatal(err)
		}
		for name, description := range described {
			if strings.Contains(description, "Docker image") {
				t.Errorf("%s %s: %q is of ipv6disc's image", def.pluginType, name, description)
			}
		}
	}
}
