package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandString(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "token"), []byte("from-file\n"), 0o600)
	absolute := filepath.Join(dir, "absolute")
	os.WriteFile(absolute, []byte("absolute-file"), 0o600)
	t.Setenv("IPV6DDNS_TEST_PASSWORD", "p,a$s")

	for in, want := range map[string]string{
		"plain":                     "plain",
		"${IPV6DDNS_TEST_PASSWORD}": "p,a$s",
		"60s,router,admin,${IPV6DDNS_TEST_PASSWORD}": "60s,router,admin,p,a$s",
		"${file:token}":            "from-file",
		"${file:" + absolute + "}": "absolute-file",
		"$${NOT_EXPANDED}":         "${NOT_EXPANDED}",
		"a $ alone, and $NAME":     "a $ alone, and $NAME",
		// Each $${ loses one $, wherever it is: no variable right after a literal $.
		"$${A} and $${B}":                         "${A} and ${B}",
		"$$${IPV6DDNS_TEST_PASSWORD}":             "$${IPV6DDNS_TEST_PASSWORD}",
		"$ ${IPV6DDNS_TEST_PASSWORD}":             "$ p,a$s",
		"$${file:token}${file:token}":             "${file:token}from-file",
		"a } before, ${file:token}":               "a } before, from-file",
		"${IPV6DDNS_TEST_PASSWORD}-${file:token}": "p,a$s-from-file",
	} {
		got, err := expandString(in, dir)
		if err != nil || got != want {
			t.Errorf("expandString(%q) = %q, %v, want %q", in, got, err, want)
		}
	}

	for in, want := range map[string]string{
		"${IPV6DDNS_TEST_UNSET}": "IPV6DDNS_TEST_UNSET is not set",
		"${file:missing}":        "reading the file",
		"${":                     "unclosed",
		"${}":                    "empty",
	} {
		if _, err := expandString(in, dir); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("expandString(%q): got %v, want an error with %q", in, err, want)
		}
	}
}

func TestNewConfigWithSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "duck-token"), []byte("01234567-89ab-cdef-0123-456789abcdef\n"), 0o600)
	t.Setenv("IPV6DDNS_TEST_ROUTER_PASSWORD", "secret")
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
tasks:
  web:
    endpoints:
      duck:
        - www
credentials:
  duck:
    provider: duckdns
    settings:
      api_token: ${file:duck-token}
discovery:
  plugins:
    router:
      type: mikrotik
      interval: 60s
      address: 192.0.2.1
      username: admin
      password: ${IPV6DDNS_TEST_ROUTER_PASSWORD}
`), 0o600)

	cfg, err := NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(cfg.Credentials["duck"].RawSettings); !strings.Contains(got, "01234567-89ab-cdef-0123-456789abcdef") {
		t.Errorf("settings: %s", got)
	}
	if got, err := cfg.Discovery.Plugins["router"].Params(); err != nil || got != "1m0s,192.0.2.1,admin,secret" {
		t.Errorf("params: %s, %v", got, err)
	}

	// The error tells where.
	os.WriteFile(path, []byte(`{"tasks": {}, "credentials": {"duck": {"provider": "duckdns", "settings": {"api_token": "${IPV6DDNS_TEST_UNSET}"}}}}`), 0o600)
	if _, err := NewConfig(path); err == nil || !strings.Contains(err.Error(), "credentials.duck.settings.api_token") {
		t.Errorf("got %v, want an error naming credentials.duck.settings.api_token", err)
	}
}
