package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"
	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var showVersion bool
var configFile string
var logLevel string
var lifetime time.Duration
var live bool
var webserverListen string

func init() {
	flag.BoolVar(&showVersion, "version", false, "Show the current version")
	flag.StringVar(&configFile, "config_file", "config.yaml", "Path to the configuration file, default: config.yaml")
	flag.StringVar(&logLevel, "log_level", "info", "Logging level (debug, info, warn, error, fatal, panic), in place of the configuration's log_level. Default: info")
	flag.DurationVar(&lifetime, "lifetime", config.DefaultLifetime, "Time to keep a discovered host entry after it has been last seen, in place of the configuration's lifetime. Default: 1h")
	flag.BoolVar(&live, "live", false, "Show the current state live on the terminal, default: false")
	flag.StringVar(&webserverListen, "webserver_listen", "", "Show the same live output to a browser, listening on this comma-separated list of addresses, host names and ports: 8053, 192.0.2.1, 192.0.2.1:8053, [2001:db8::1]:8053, myhost:8053 (no port: 80), in place of the configuration's webserver_listen. Default: disabled")
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Print(PrintVersion())
		os.Exit(0)
	}

	sugar, level := initializeLogger()
	ipv6ddns.Version = version

	config, err := config.NewConfig(configFile)
	if err != nil {
		sugar.Fatalf("error reading config: %s", err)
	}
	if err := applyConfigSettings(config, given(), level); err != nil {
		sugar.Fatalf("error in config: %s", err)
	}

	config.Lifetime.Duration = lifetime
	worker, err := ipv6ddns.NewWorker(sugar, config)
	if err != nil {
		sugar.Fatalf("error in config: %s", err)
	}

	for name, pCfg := range config.Discovery.Plugins {
		params, err := pCfg.PluginParams()
		if err != nil {
			sugar.Fatalf("plugin %s: %s", name, err)
		}
		p, err := plugins.Create(pCfg.Type, name, params, lifetime)
		if err != nil {
			sugar.Fatalf("can't create plugin %s: %s", pCfg.Type, err)
		}

		worker.RegisterPlugin(p)
	}

	// Stops on SIGINT and SIGTERM, letting the updates running end.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = worker.Start(ctx)
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	var servers []*http.Server
	if webserverListen != "" {
		entries, err := listen.Parse(strings.Split(webserverListen, ","), webserverPort)
		if err != nil {
			sugar.Fatalf("webserver.listen: %s", err)
		}
		listeners, err := listen.Listen(entries)
		if err != nil {
			sugar.Fatalf("web server failed: %s", err)
		}
		for _, listener := range listeners {
			server := &http.Server{Handler: webHandler(worker), ReadHeaderTimeout: 10 * time.Second}
			servers = append(servers, server)
			go func() {
				sugar.Infof("Starting web server on %s", listener.Addr())
				if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
					sugar.Fatalf("web server failed: %s", err)
				}
			}()
		}
	}

	if live {
		liveOutput := make(chan string)
		go func() {
			for {
				select {
				case liveOutput <- wrapPrettyPrint(worker, "", false):
				case <-ctx.Done():
					return
				}
				time.Sleep(1 * time.Second)
			}
		}()
		// The terminal takes the keys, Ctrl-C too: it returns on them.
		terminal.LiveOutput(liveOutput)
		stop()
	}
	<-ctx.Done()

	sugar.Info("stopping")
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, server := range servers {
		server.Shutdown(shutdown)
	}
	if err := worker.Shutdown(shutdown); err != nil {
		sugar.Errorf("%s: the updates still running are cut", err)
	}
}

// shutdownTimeout is how long the updates running get to end, when stopping.
const shutdownTimeout = 30 * time.Second

// webHandler serves the state: as text, JSON and Prometheus metrics, with the sensible data
// hidden, as the server has no authentication. /healthz answers while the process runs.
func webHandler(worker *ipv6ddns.Worker) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", statusHandler(worker))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.Encode(worker.Status(true))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		worker.Status(true).WriteMetrics(w)
	})
	return mux
}

// statusHandler serves the state, with the sensible data hidden: the page has no authentication.
func statusHandler(worker *ipv6ddns.Worker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(wrapPrettyPrint(worker, "", true)))
	})
}

func wrapPrettyPrint(worker *ipv6ddns.Worker, prefix string, hideSensible bool) string {
	var result strings.Builder
	fmt.Fprint(&result, worker.PrettyPrint(prefix, hideSensible))
	fmt.Fprint(&result, prefix, PrintVersion())
	return result.String()
}

// given returns the flags given on the command line, which win over the configuration.
func given() map[string]bool {
	flags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { flags[f.Name] = true })
	return flags
}

// webserverPort is that of the web server's entries that give none.
const webserverPort = config.DefaultWebserverPort

// applyConfigSettings takes the settings of the configuration that are flags too, for the flags
// not given: the lifetime, the logging level and the web server's addresses.
func applyConfigSettings(cfg config.Config, given map[string]bool, level zap.AtomicLevel) error {
	if !given["lifetime"] {
		lifetime = cfg.Lifetime.Duration
	}
	if lifetime <= 0 {
		return fmt.Errorf("invalid lifetime %s: it must be positive", lifetime)
	}
	if !given["webserver_listen"] && len(cfg.Webserver.Listen) > 0 {
		webserverListen = strings.Join(cfg.Webserver.Listen, ",")
	}
	if !given["log_level"] && cfg.LogLevel != "" {
		zapLevel, err := getLogLevel(cfg.LogLevel)
		if err != nil {
			return fmt.Errorf("invalid log_level %q", cfg.LogLevel)
		}
		if !live {
			level.SetLevel(zapLevel)
		}
	}
	return nil
}

func initializeLogger() (*zap.SugaredLogger, zap.AtomicLevel) {
	zapLevel, err := getLogLevel(logLevel)
	if err != nil {
		log.Fatalf("invalid log level: %s", logLevel)
	}

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
