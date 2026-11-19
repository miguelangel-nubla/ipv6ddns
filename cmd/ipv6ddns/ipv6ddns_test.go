package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"
	"go.uber.org/zap"
)

func TestExampleConfig(t *testing.T) {
	// The example takes the router's password from the environment.
	t.Setenv("ROUTER_PASSWORD", "example")
	cfg, err := config.NewConfig("example.config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipv6ddns.NewWorker(zap.NewNop().Sugar(), cfg); err != nil {
		t.Fatal(err)
	}
	for name, p := range cfg.Discovery.Plugins {
		params, err := p.PluginParams()
		if err != nil {
			t.Fatalf("plugin %s: %v", name, err)
		}
		if _, err := plugins.Create(p.Type, name, params, time.Hour); err != nil {
			t.Errorf("plugin %s: %v", name, err)
		}
	}
}

func TestStatusHandlerHidesSensibleData(t *testing.T) {
	const secret = "SECRET-91c2"
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(`
tasks:
  web:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
    endpoints:
      duck:
        - www
    ipv4:
      interval: 1h
      lifetime: 1h
      command: curl
      args: ["https://example.com/ip?key=`+secret+`"]
credentials:
  duck:
    provider: duckdns
    settings:
      api_token: 01234567-89ab-cdef-0123-456789abcdef
discovery:
  plugins:
    router:
      type: mikrotik
      params: 60s,192.0.2.1,admin,`+secret+`
`), 0o600)
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := ipv6ddns.NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := webHandler(worker)
	for path, want := range map[string]struct{ contentType, body string }{
		"/":            {"text/plain; charset=utf-8", "www.duckdns.org"},
		"/other":       {"text/plain; charset=utf-8", "www.duckdns.org"},
		"/healthz":     {"text/plain; charset=utf-8", "ok"},
		"/status.json": {"application/json", `"domain": "www.duckdns.org"`},
		"/metrics":     {"text/plain; version=0.0.4; charset=utf-8", `ipv6ddns_hostname_addresses{provider="duckdns",endpoint="duck",hostname="www.duckdns.org"} 0`},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		body := response.Body.String()
		for _, s := range []string{secret, "01234567-89ab-cdef-0123-456789abcdef"} {
			if strings.Contains(body, s) {
				t.Errorf("%s: %s is on the page:\n%s", path, s, body)
			}
		}
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != want.contentType || !strings.Contains(body, want.body) {
			t.Errorf("%s: %d %s, want %s with %q:\n%s", path, response.Code, response.Header().Get("Content-Type"), want.contentType, want.body, body)
		}
		if path == "/status.json" && !json.Valid(response.Body.Bytes()) {
			t.Errorf("%s: invalid JSON", path)
		}
	}
}

func TestApplyConfigSettings(t *testing.T) {
	defer func(l time.Duration, w, lv string) { lifetime, webserverListen, logLevel = l, w, lv }(lifetime, webserverListen, logLevel)

	cfg := config.Config{LogLevel: "debug", Webserver: config.Webserver{Listen: config.StringList{"8053", "[::1]:8054"}}}
	cfg.Lifetime.Duration = 10 * time.Minute

	// The configuration's, for the flags not given.
	lifetime, webserverListen, logLevel = time.Hour, "", "info"
	level := zap.NewAtomicLevelAt(zap.InfoLevel)
	if err := applyConfigSettings(cfg, map[string]bool{}, level); err != nil {
		t.Fatal(err)
	}
	if lifetime != 10*time.Minute || webserverListen != "8053,[::1]:8054" || level.Level() != zap.DebugLevel {
		t.Errorf("from the configuration: %s, %q, %s", lifetime, webserverListen, level.Level())
	}

	// The flags given win.
	lifetime, webserverListen, logLevel = 2*time.Hour, "9000", "warn"
	level = zap.NewAtomicLevelAt(zap.WarnLevel)
	if err := applyConfigSettings(cfg, map[string]bool{"lifetime": true, "webserver_listen": true, "log_level": true}, level); err != nil {
		t.Fatal(err)
	}
	if lifetime != 2*time.Hour || webserverListen != "9000" || level.Level() != zap.WarnLevel {
		t.Errorf("the flags: %s, %q, %s", lifetime, webserverListen, level.Level())
	}

	if err := applyConfigSettings(config.Config{LogLevel: "loud"}, map[string]bool{"lifetime": true}, level); err == nil {
		t.Error("a bad log level: want an error")
	}

	// A zero lifetime in the file: an error, unless the flag gives one.
	zero := config.Config{}
	if err := applyConfigSettings(zero, map[string]bool{}, level); err == nil {
		t.Error("lifetime 0: want an error")
	}
	lifetime = 30 * time.Minute
	if err := applyConfigSettings(zero, map[string]bool{"lifetime": true}, level); err != nil || lifetime != 30*time.Minute {
		t.Errorf("lifetime 0 and -lifetime 30m: %v, %s", err, lifetime)
	}
}
