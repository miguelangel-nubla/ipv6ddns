package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// The flags: the rest is the configuration file's.
var (
	configFile  string
	live        bool
	showVersion bool
)

// configFiles are where the configuration is looked for without --config, in this order: the
// working directory's, as in a container, then the system's, as a package installs it.
var configFiles = []string{"config.yaml", "/etc/ipv6ddns/config.yaml"}

// findConfig is the configuration file: the one given, or without one the first of configFiles
// there is.
func findConfig(given string) (string, error) {
	if given != "" {
		return given, nil
	}
	for _, file := range configFiles {
		if _, err := os.Stat(file); err == nil {
			return file, nil
		}
	}
	return "", fmt.Errorf("no configuration file: there is no %s. Give one with --config", strings.Join(configFiles, " nor "))
}

// reference is where every key of the configuration file is told.
const reference = "https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/reference/configuration.md"

func init() {
	defineFlags()
}

// defineFlags defines the flags on flag.CommandLine, each with its default: the tests define them
// again on a new one, as a flag set can't forget what it was given.
func defineFlags() {
	flag.StringVar(&configFile, "config", "", "The configuration `file`, YAML or JSON: the names to keep, the providers, the discovery, the level of the log and the web server. Without it: "+strings.Join(configFiles, ", or ")+", the first there is")
	flag.BoolVar(&live, "live", false, "Show the state in the terminal, updating, instead of the log")
	flag.BoolVar(&showVersion, "version", false, "Show the version, and exit")
	flag.Usage = usage
}

// usage lists the flags as flag does, but each with two dashes, and tells where the rest is.
func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	flag.VisitAll(func(f *flag.Flag) {
		// The kind of its value, none for a boolean, and its default when it has one.
		kind, text := flag.UnquoteUsage(f)
		line := "  --" + f.Name
		if kind != "" {
			line += " " + kind
		}
		line += "\n    \t" + text
		switch {
		case f.DefValue == "" || f.DefValue == "false":
		case kind == "string":
			line += fmt.Sprintf(" (default %q)", f.DefValue)
		default:
			line += fmt.Sprintf(" (default %s)", f.DefValue)
		}
		fmt.Fprintln(flag.CommandLine.Output(), line)
	})
	fmt.Fprintf(flag.CommandLine.Output(), "\nEverything else is in the configuration file, whose keys are at:\n  %s\n", reference)
}

// unexpectedArgs is the error of the words left after the flags. There are none to give: flag
// stops at the first, so the flags after it would be left out without a word, as --config
// after "--live false".
func unexpectedArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected argument %q: ipv6ddns takes only flags. To turn a boolean flag off, write --name=false", args[0])
}

func main() {
	flag.Parse()

	if err := unexpectedArgs(flag.Args()); err != nil {
		fmt.Fprintln(flag.CommandLine.Output(), err)
		flag.Usage()
		os.Exit(2)
	}

	if showVersion {
		fmt.Print(PrintVersion())
		os.Exit(0)
	}

	sugar, level := initializeLogger()
	ipv6ddns.Version = version
	// Of a configuration that can't be used: its own exit code, so that a service manager doesn't
	// start it again and again, as nothing changes until the configuration does.
	inConfig := sugar.WithOptions(zap.WithFatalHook(exitWith(exitConfig)))

	configFile, err := findConfig(configFile)
	if err != nil {
		inConfig.Fatal(err)
	}
	config, err := config.NewConfig(configFile)
	if err != nil {
		inConfig.Fatalf("error reading config: %s", err)
	}
	if err := setLogLevel(config.LogLevel, level); err != nil {
		inConfig.Fatalf("error in config: %s", err)
	}

	worker, err := ipv6ddns.NewWorker(sugar, config)
	if err != nil {
		inConfig.Fatalf("error in config: %s", err)
	}

	// The plugins get the lifetime of the discovery: a family's own, when given, is the state's
	// to put in its place.
	plugins, err := config.Discovery.NewPlugins()
	if err != nil {
		inConfig.Fatalf("can't create the plugins: %s", err)
	}
	for _, p := range plugins {
		worker.RegisterPlugin(p)
	}

	// Stops on SIGINT and SIGTERM, letting the updates running end.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The terminal is taken before anything starts, so that without one nothing does, and given
	// back before every exit: Fatalf runs no defers, and would leave it raw.
	closeTerminal := func() {}
	if live {
		if err := terminal.Init(); err != nil {
			sugar.Fatalf("--live needs a terminal: %s", err)
		}
		closeTerminal = sync.OnceFunc(terminal.Close)
	}
	defer closeTerminal()

	// The web servers on the HTTPS entries of the listeners they share with a resolver: the
	// resolver opens them, and gives the web server every path but its DNS over HTTPS.
	webNames := slices.Sorted(maps.Keys(config.Webservers))
	for _, name := range webNames {
		for _, shared := range config.Webservers[name].Shared {
			worker.SetWeb(strings.TrimPrefix(shared.Resolver, "resolvers."), shared.Listener, allowOnly(webHandler(worker), shared.Allow))
		}
	}
	// The web servers' sockets, before anything starts: one that can't listen, as on a port
	// another program holds, ends the start with nothing begun to undo, no resolver listening
	// and no Home Assistant device announced.
	sockets, err := listenWeb(config.Webservers, webNames)
	if err != nil {
		closeTerminal()
		sugar.Fatal(err)
	}
	err = worker.Start(ctx)
	if err != nil {
		for _, s := range sockets {
			s.listener.Close()
		}
		closeTerminal()
		sugar.Fatalf("can't start worker: %s", err)
	}

	// The web servers: of HTTP on their plain entries, and of HTTPS, HTTP/1.1 and HTTP/2, with
	// their certificates, on the others; each with its allow. One that fails while serving stops
	// it all as a signal does, the updates running let end, and the process ends with 1.
	var servers []*http.Server
	var failed atomic.Bool
	for _, s := range sockets {
		var tlsConfig *tls.Config
		scheme := "http://"
		if s.entry.Certificate != "" {
			tlsConfig, scheme = worker.TLS(s.entry.Certificate, "h2", "http/1.1"), "https://"
		}
		worker.WebListening(s.entry.Listener, scheme+s.listener.Addr().String())
		server := newWebServer(allowOnly(webHandler(worker), s.entry.Allow), tlsConfig)
		servers = append(servers, server)
		go func() {
			if err := serveWeb(sugar, s.path, server, s.listener); err != nil {
				sugar.Errorf("%s failed: %s: stopping", s.path, err)
				failed.Store(true)
				stop()
			}
		}()
	}
	for _, name := range webNames {
		web := config.Webservers[name]
		for _, shared := range web.Shared {
			sugar.Infof("Starting %s on %s, of listeners.%s, whose %s serves DNS over HTTPS at %s", web.Path, strings.Join(shared.Lines, ", "), shared.Listener, shared.Resolver, resolver.DoHPath)
		}
	}

	if live {
		liveOutput := make(chan pretty.Page)
		go func() {
			for {
				select {
				case liveOutput <- statusPage(worker, false):
				case <-ctx.Done():
					return
				}
				time.Sleep(1 * time.Second)
			}
		}()
		// The terminal takes the keys, Ctrl-C too: Run returns on them, and when ctx ends, as on
		// a SIGTERM, which is no key. The terminal is given back before the wait for the updates.
		terminal.RunPages(ctx, liveOutput)
		closeTerminal()
		stop()
	}
	<-ctx.Done()
	// The signals are the system's again: a second one ends the process without the wait.
	stop()

	sugar.Info("stopping")
	// The web servers first, in a time of their own: the updates running have all of theirs after.
	if err := stopWeb(servers); err != nil {
		sugar.Errorf("web server: %s: requests still in progress were cut off", err)
	}
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := worker.Shutdown(shutdown); err != nil {
		sugar.Errorf("%s: updates still running were cut off", err)
	}
	if failed.Load() {
		closeTerminal()
		os.Exit(1)
	}
}

// exitConfig is the exit code of a configuration that can't be used: EX_CONFIG, of sysexits.h.
// The unit of systemd doesn't restart the service of it, RestartPreventExitStatus. Any other
// failure, as a port another program holds, ends with 1, and is tried again.
const exitConfig = 78

// exitWith ends the process with its code, after a fatal entry is written.
type exitWith int

func (code exitWith) OnWrite(*zapcore.CheckedEntry, []zapcore.Field) {
	os.Exit(int(code))
}

// webSocket is a socket a web server listens on, of one of its entries.
type webSocket struct {
	path     string
	entry    config.WebEntry
	listener net.Listener
}

// listenWeb opens the sockets of the web servers' own entries, in the order of their names. Of
// one that can't listen, those opened before are closed, and the error is the web server's.
func listenWeb(webservers map[string]config.Webserver, names []string) ([]webSocket, error) {
	var sockets []webSocket
	for _, name := range names {
		web := webservers[name]
		for _, entry := range web.Entries {
			listeners, err := listen.Listen([]listen.Entry{entry.Entry})
			if err != nil {
				for _, s := range sockets {
					s.listener.Close()
				}
				return nil, fmt.Errorf("%s failed: %w", web.Path, err)
			}
			for _, l := range listeners {
				sockets = append(sockets, webSocket{web.Path, entry, l})
			}
		}
	}
	return sockets, nil
}

// shutdownTimeout is how long the updates running get to end, when stopping.
const shutdownTimeout = 30 * time.Second

// The times of a web server. They are variables for the tests, which shorten them.
var (
	// A request, whole, with its body: a router's update is a line. One that doesn't come in it,
	// from anyone, before any password, is ended.
	webReadTimeout = 30 * time.Second
	// An answer, from the request's headers on: more than the slowest takes, which is an update
	// whose body took all of webReadTimeout, and then refusedWait for a wrong password.
	webWriteTimeout = time.Minute
	// A connection kept open with no request on it.
	webIdleTimeout = 2 * time.Minute
	// The requests in progress, of all the web servers, when stopping: those left then are cut off.
	webShutdownTimeout = 5 * time.Second
)

// newWebServer is a web server of the handler, with the times of one, and over HTTPS with a TLS
// configuration.
func newWebServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: min(10*time.Second, webReadTimeout),
		ReadTimeout:       webReadTimeout,
		WriteTimeout:      webWriteTimeout,
		IdleTimeout:       webIdleTimeout,
	}
}

// stopWeb shuts the web servers down, all at once, letting the requests in progress end within
// webShutdownTimeout: after it they are cut off, which is the error, the first.
func stopWeb(servers []*http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), webShutdownTimeout)
	defer cancel()
	errs := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Go(func() {
			if errs[i] = server.Shutdown(ctx); errs[i] != nil {
				_ = server.Close()
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// webHandler serves the state: as a page, of HTML for a browser and of text for the rest, as JSON
// and as Prometheus metrics, with the sensible data hidden, as the server has no authentication. /healthz answers while the process runs, and its
// resolvers answer: 503 when one doesn't. A write that fails is of a client gone: nothing to do.
func webHandler(worker *ipv6ddns.Worker) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", statusHandler(worker))
	mux.HandleFunc("GET /status.txt", func(w http.ResponseWriter, r *http.Request) {
		writeStatusText(w, worker)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if err := worker.Healthy(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, err.Error()+"\n")
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(worker.Status(true))
	})
	// Of any method: a router may send its update as a POST.
	mux.Handle(pushPath, pushHandler(worker))
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = worker.Status(true).WriteMetrics(w)
	})
	return mux
}

// statusHandler serves the state, with the sensible data hidden: the page has no authentication.
// To what asks for HTML, as a browser does, it is the page with its colors; to the rest, as curl,
// the same page as text, which /status.txt is to all.
func statusHandler(worker *ipv6ddns.Worker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A cache keeps one answer for each Accept.
		w.Header().Set("Vary", "Accept")
		if !acceptsHTML(r) {
			writeStatusText(w, worker)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The page is text and its style: nothing in it runs or loads, whatever a name on the
		// network has in it.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.WriteString(w, statusHTMLHead+statusPage(worker, true).HTML()+statusHTMLTail)
	})
}

func writeStatusText(w http.ResponseWriter, worker *ipv6ddns.Worker) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, statusPage(worker, true).String())
}

// acceptsHTML is whether the request asks for HTML by name: a browser does, and curl, of */*,
// doesn't.
func acceptsHTML(r *http.Request) bool {
	for _, accept := range r.Header.Values("Accept") {
		for media := range strings.SplitSeq(accept, ",") {
			media, params, _ := strings.Cut(media, ";")
			if strings.EqualFold(strings.TrimSpace(media), "text/html") && !notWanted(params) {
				return true
			}
		}
	}
	return false
}

// notWanted is whether the parameters of a media type of Accept have a quality of 0: not wanted.
func notWanted(params string) bool {
	for param := range strings.SplitSeq(params, ";") {
		if q, ok := strings.CutPrefix(strings.TrimSpace(param), "q="); ok {
			return strings.Trim(q, "0.") == "" && q != ""
		}
	}
	return false
}

// statusPage is the page of the worker, and under it the version.
func statusPage(worker *ipv6ddns.Worker, hideSensible bool) pretty.Page {
	page := worker.Page("", hideSensible)
	page.Add(pretty.As(pretty.Detail, strings.TrimSuffix(PrintVersion(), "\n")))
	return page
}

// The page as HTML: the text in a pre, each role with its color, on the light or the dark theme
// of the browser. All of it is here: the page is served on networks with no way out, and asks
// for nothing from elsewhere. Every color is of a contrast of 4.5 or more on its ground.
const statusHTMLHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>ipv6ddns</title>
<style>
:root {
	--bg: #ffffff; --fg: #1d2530;
	--h: #1d2530; --n: #0f3a8a; --ok: #1d7a3e; --w: #8a5200; --e: #c0262d; --d: #5d6877;
}
@media (prefers-color-scheme: dark) {
	:root {
		--bg: #12161c; --fg: #dde3ea;
		--h: #f1f4f8; --n: #9cc0ff; --ok: #5fcf83; --w: #e7b04f; --e: #ff7b7b; --d: #8c97a6;
	}
}
body { margin: 0; background: var(--bg); color: var(--fg); }
pre {
	margin: 0; padding: 14px 16px; overflow-x: auto; tab-size: 4;
	font: 13px/1.45 ui-monospace, "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", monospace;
}
.h { color: var(--h); font-weight: 600; }
.n { color: var(--n); }
.ok { color: var(--ok); }
.w { color: var(--w); }
.e { color: var(--e); font-weight: 600; }
.d { color: var(--d); }
</style>
</head>
<body>
<pre>`

const statusHTMLTail = `</pre>
</body>
</html>
`

// serveWeb serves the web server at path, as webservers.main, on the listener until it is shut
// down: over HTTPS, when it has a TLS configuration. Its shutdown is no error.
func serveWeb(logger *zap.SugaredLogger, path string, server *http.Server, listener net.Listener) error {
	var err error
	if server.TLSConfig != nil {
		logger.Infof("Starting %s on https://%s", path, listener.Addr())
		err = server.ServeTLS(listener, "", "")
	} else {
		logger.Infof("Starting %s on %s", path, listener.Addr())
		err = server.Serve(listener)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// allowOnly has h answer the clients in allow alone, the others 403: nil, everyone.
func allowOnly(h http.Handler, allow []netip.Prefix) http.Handler {
	if allow == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !slices.ContainsFunc(allow, func(p netip.Prefix) bool { return p.Contains(client.Addr().WithZone("").Unmap()) }) {
			http.Error(w, "forbidden: this address is not one the web server answers", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// webserverPort is that of the web server's entries that give none.
const webserverPort = config.DefaultWebserverPort

// setLogLevel gives the log the level of the configuration, info without one. With --live nothing
// writes over the terminal: the level stays, and one there is none of is still an error.
func setLogLevel(logLevel string, level zap.AtomicLevel) error {
	if logLevel == "" {
		return nil
	}
	zapLevel, err := getLogLevel(logLevel)
	if err != nil {
		return fmt.Errorf("invalid log_level %q", logLevel)
	}
	if !live {
		level.SetLevel(zapLevel)
	}
	return nil
}

// initializeLogger makes the log, at info until the configuration is read, which says its level:
// what is wrong with the configuration is logged as an error, at any level it could say.
func initializeLogger() (*zap.SugaredLogger, zap.AtomicLevel) {
	zapLevel := zap.InfoLevel
	if live {
		zapLevel = zapcore.FatalLevel
	}

	level := zap.NewAtomicLevelAt(zapLevel)
	cfg := zap.NewProductionConfig()
	cfg.Level = level
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	return zap.Must(cfg.Build()).Sugar(), level
}

func getLogLevel(level string) (zapcore.Level, error) {
	var zapLevel zapcore.Level
	err := zapLevel.UnmarshalText([]byte(level))
	if err != nil {
		return zap.InfoLevel, err
	}
	return zapLevel, nil
}

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func PrintVersion() string {
	return fmt.Sprintf("ipv6ddns %s, commit %s, built at %s\n", version, commit, date)
}
