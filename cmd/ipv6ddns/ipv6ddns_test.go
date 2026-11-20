package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
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
	// It is what a configuration starts from: nothing deprecated in it.
	if len(cfg.Warnings) != 0 {
		t.Errorf("the example has deprecated forms: %v", cfg.Warnings)
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

// A word after the flags ends them: an error, rather than the flags after it left out.
func TestUnexpectedArgs(t *testing.T) {
	parse := func(args ...string) error {
		flags := flag.NewFlagSet("ipv6ddns", flag.ContinueOnError)
		flags.Bool("live", false, "")
		file := flags.String("config_file", "config.yaml", "")
		if err := flags.Parse(args); err != nil {
			t.Fatal(err)
		}
		if err := unexpectedArgs(flags.Args()); err != nil {
			return err
		}
		if want := "x"; *file != want {
			t.Errorf("%q: config_file %q, want %q", args, *file, want)
		}
		return nil
	}
	if err := parse("-live=false", "-config_file", "x"); err != nil {
		t.Errorf("no words left: %v", err)
	}
	for _, args := range [][]string{{"-live", "false", "-config_file", "x"}, {"false"}} {
		err := parse(args...)
		if err == nil || !strings.Contains(err.Error(), `"false"`) || !strings.Contains(err.Error(), "-name=false") {
			t.Errorf("%q: %v, want an error naming \"false\" and -name=false", args, err)
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
sources:
  echo:
    type: http
    urls: ["https://user:`+secret+`@echo.example/ip/`+secret+`?token=`+secret+`"]
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
		// Another method is no other page: the report, hidden the same.
		post := httptest.NewRecorder()
		handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, path, nil))
		if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), "www.duckdns.org") || strings.Contains(post.Body.String(), secret) {
			t.Errorf("POST %s: %d, want the report without %s:\n%s", path, post.Code, secret, post.Body.String())
		}
		for _, s := range []string{secret, "01234567-89ab-cdef-0123-456789abcdef"} {
			if strings.Contains(body, s) {
				t.Errorf("%s: %s is on the page:\n%s", path, s, body)
			}
		}
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != want.contentType || !strings.Contains(body, want.body) {
			t.Errorf("%s: %d %s, want %s with %q:\n%s", path, response.Code, response.Header().Get("Content-Type"), want.contentType, want.body, body)
		}
		// The http source's url, down to its host.
		if path == "/" && !strings.Contains(body, "from https://echo.example,") {
			t.Errorf("%s: the host of the http source's url isn't on the page:\n%s", path, body)
		}
		if path == "/status.json" && !json.Valid(response.Body.Bytes()) {
			t.Errorf("%s: invalid JSON", path)
		}
	}
}

func TestApplyConfigSettings(t *testing.T) {
	defer func(l time.Duration, w, lv string, lo bool) { lifetime, webserverListen, logLevel, live = l, w, lv, lo }(lifetime, webserverListen, logLevel, live)

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

	// A flag given empty wins too: no web server, whatever the configuration says.
	webserverListen = ""
	if err := applyConfigSettings(cfg, map[string]bool{"webserver_listen": true}, level); err != nil || webserverListen != "" {
		t.Errorf("-webserver_listen \"\": %v, %q", err, webserverListen)
	}

	// With -live nothing writes over the terminal: the level stays, and a bad one is still an error.
	live = true
	level = zap.NewAtomicLevelAt(zap.FatalLevel)
	if err := applyConfigSettings(cfg, map[string]bool{}, level); err != nil || level.Level() != zap.FatalLevel {
		t.Errorf("-live: %v, level %s, want fatal", err, level.Level())
	}
	if err := applyConfigSettings(config.Config{LogLevel: "loud"}, map[string]bool{"lifetime": true}, level); err == nil {
		t.Error("-live and a bad log level: want an error")
	}
	live = false

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

// The web server's entries without a port are at 8053, as every example and the health check have
// it: not at 80.
func TestWebserverDefaultPort(t *testing.T) {
	entries, err := listen.Parse([]string{"192.0.2.1", "10.2.3.0/24", "myhost", "9000"}, webserverPort)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"8053", "8053", "8053", "9000"} {
		if entries[i].Port != want {
			t.Errorf("%v: port %s, want %s", entries[i], entries[i].Port, want)
		}
	}
}
