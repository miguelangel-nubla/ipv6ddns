package config

import (
	"fmt"
	"strings"
	"testing"
)

// An allow given that names nobody is refused, wherever it is: taken for none given, it would be
// the default, which lets more clients in than any list, everyone for a web server. Left out, it
// is the default, as before.
func TestEmptyAllow(t *testing.T) {
	t.Setenv("IPV6DDNS_TEST_EMPTY", "")
	config := func(allow map[string]string) string {
		at := func(path string) string {
			if a, ok := allow[path]; ok {
				return "allow: " + a
			}
			return "# no allow"
		}
		return fmt.Sprintf(`
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
listeners:
  lan:
    listen:
      - dns://127.0.0.1:8053
      - http://127.0.0.1:8080
    %s
webservers:
  main:
    listeners:
      - lan
    %s
resolvers:
  home:
    listeners:
      - lan
    upstream:
      - 1.1.1.1
    %s
    updates:
      %s
      keys:
        nas:
          secret: %s
          %s
          permissions:
            - names:
                zone: home.arpa
tasks: {}
`, at("listeners.lan"), at("webservers.main"), at("resolvers.home"), at("resolvers.home.updates"), testSecretYAML, at("resolvers.home.updates.keys.nas"))
	}
	paths := []string{"listeners.lan", "webservers.main", "resolvers.home", "resolvers.home.updates", "resolvers.home.updates.keys.nas"}

	if _, err := loadConfig(t, config(nil)); err != nil {
		t.Fatalf("no allow: %v", err)
	}
	every := map[string]string{}
	for _, p := range paths {
		every[p] = "192.168.1.0/24"
	}
	if _, err := loadConfig(t, config(every)); err != nil {
		t.Fatalf("every allow: %v", err)
	}

	for _, path := range paths {
		// [""] is the schema's to refuse, as an item can't be empty: [" "] is no less empty.
		for _, empty := range []string{`[]`, `""`, `" , "`, `[" "]`, `${IPV6DDNS_TEST_EMPTY}`, `[""]`} {
			allow := map[string]string{}
			for _, p := range paths {
				allow[p] = "192.168.1.0/24"
			}
			allow[path] = empty
			_, err := loadConfig(t, config(allow))
			want := path + ".allow is empty: give the clients"
			if empty == `[""]` {
				want = path + ".allow.0: String length must be greater than or equal to 1"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: allow: %s: got %v, want %q", path, empty, err, want)
			}
		}
	}
}
