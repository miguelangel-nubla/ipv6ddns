package main

import (
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
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
	created, err := cfg.Discovery.NewPlugins()
	if err != nil || len(created) != len(cfg.Discovery.Plugins) {
		t.Errorf("the plugins: %d of %d, %v", len(created), len(cfg.Discovery.Plugins), err)
	}
}

// resetFlags gives the test the flags as a new process has them, none given, and leaves them so:
// a flag set can't forget what it was given, so the test has one of its own, and the process's,
// which has those of the tests too, comes back after it.
func resetFlags(t *testing.T) {
	t.Helper()
	original := flag.CommandLine
	define := func() {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		flag.CommandLine.Usage = func() { flag.Usage() }
		defineFlags()
	}
	define()
	t.Cleanup(func() {
		// The values the flags were given are of the variables, which both sets have.
		configFile, live, showVersion = "config.yaml", false, false
		define()
		flag.CommandLine = original
	})
}

// The command has three flags, and no other: the rest is the configuration file's.
func TestFlags(t *testing.T) {
	resetFlags(t)
	var names []string
	flag.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	if !slices.Equal(names, []string{"config_file", "live", "version"}) {
		t.Errorf("the flags are %v", names)
	}
	if err := flag.CommandLine.Parse(nil); err != nil || configFile != "config.yaml" || live || showVersion {
		t.Errorf("without flags: config_file %q, live %v, version %v, %v", configFile, live, showVersion, err)
	}
	if err := flag.CommandLine.Parse([]string{"-config_file", "other.yaml", "-live", "-version"}); err != nil || configFile != "other.yaml" || !live || !showVersion {
		t.Errorf("with them: config_file %q, live %v, version %v, %v", configFile, live, showVersion, err)
	}
}

// What was a flag is one no more, as any the command never had: its setting is a key of the
// configuration file, which the usage tells where to find.
func TestOldFlagsAreUnknown(t *testing.T) {
	for _, old := range []string{"-log_level=debug", "-lifetime=1h", "-webserver_listen=8053", "-log_level", "-webserver_listen"} {
		resetFlags(t)
		var out strings.Builder
		flag.CommandLine.SetOutput(&out)
		name, _, _ := strings.Cut(old, "=")
		if err := flag.CommandLine.Parse([]string{old, "debug"}); err == nil || err.Error() != "flag provided but not defined: "+name {
			t.Errorf("%s: %v, want it not defined", old, err)
		}
		if !strings.Contains(out.String(), "Usage of") || !strings.Contains(out.String(), reference) {
			t.Errorf("%s: no usage with where the configuration is told:\n%s", old, out.String())
		}
	}
}

// The usage, which -h and -help show too, lists the flags there are, and tells where the keys
// of the configuration file are: the reference, which is there.
func TestUsage(t *testing.T) {
	for _, help := range []string{"-h", "-help"} {
		resetFlags(t)
		var out strings.Builder
		flag.CommandLine.SetOutput(&out)
		if err := flag.CommandLine.Parse([]string{help}); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("%s: %v", help, err)
		}
		usage := out.String()
		for _, want := range []string{"Usage of", "  -config_file string\n", "  -live\n", "  -version\n", "\nEverything else is in the configuration file, whose keys are at:\n  " + reference + "\n"} {
			if !strings.Contains(usage, want) {
				t.Errorf("%s: no %q in:\n%s", help, want, usage)
			}
		}
		for _, gone := range []string{"log_level", "lifetime", "webserver_listen"} {
			if strings.Contains(usage, gone) {
				t.Errorf("%s: %s is in the usage:\n%s", help, gone, usage)
			}
		}
	}
	const prefix = "https://github.com/miguelangel-nubla/ipv6ddns/blob/main/"
	if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(strings.TrimPrefix(reference, prefix)))); err != nil || !strings.HasPrefix(reference, prefix) {
		t.Errorf("the reference, %s: %v", reference, err)
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
      args:
        - "https://example.com/ip?key=`+secret+`"
sources:
  echo:
    type: http
    urls:
      - "https://user:`+secret+`@echo.example/ip/`+secret+`?token=`+secret+`"
credentials:
  duck:
    provider: duckdns
    settings:
      api_token: 01234567-89ab-cdef-0123-456789abcdef
discovery:
  plugins:
    router:
      type: mikrotik
      interval: 60s
      address: 192.0.2.1
      username: admin
      password: "`+secret+`"
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

// The level of the log is the configuration's: info without one.
func TestSetLogLevel(t *testing.T) {
	defer func(lo bool) { live = lo }(live)

	level := zap.NewAtomicLevelAt(zap.InfoLevel)
	if err := setLogLevel("", level); err != nil || level.Level() != zap.InfoLevel {
		t.Errorf("no log_level: %v, %s", err, level.Level())
	}
	if err := setLogLevel("debug", level); err != nil || level.Level() != zap.DebugLevel {
		t.Errorf("log_level debug: %v, %s", err, level.Level())
	}
	if err := setLogLevel("loud", level); err == nil || err.Error() != `invalid log_level "loud"` || level.Level() != zap.DebugLevel {
		t.Errorf("a bad log level: %v, %s", err, level.Level())
	}

	// With -live nothing writes over the terminal: the level stays, and a bad one is still an error.
	live = true
	logger, level := initializeLogger()
	if err := setLogLevel("debug", level); err != nil || level.Level() != zap.FatalLevel || logger.Desugar().Core().Enabled(zap.ErrorLevel) {
		t.Errorf("-live: %v, level %s, want fatal", err, level.Level())
	}
	if err := setLogLevel("loud", level); err == nil {
		t.Error("-live and a bad log level: want an error")
	}
	live = false
	if logger, level := initializeLogger(); level.Level() != zap.InfoLevel || !logger.Desugar().Core().Enabled(zap.InfoLevel) {
		t.Errorf("the log before the configuration is read: %s", level.Level())
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

// /healthz fails while a resolver doesn't answer: here, one never started.
func TestHealthzResolver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(`
resolvers:
  lan:
    listen: 192.0.2.1
    upstream: 192.0.2.53
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
tasks: {}
`), 0o600)
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := ipv6ddns.NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	webHandler(worker).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "resolver lan isn't serving: not started\n" {
		t.Errorf("%d %q", response.Code, response.Body.String())
	}
}
