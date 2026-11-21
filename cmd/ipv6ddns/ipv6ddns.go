package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"
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

// reference is where every key of the configuration file is told.
const reference = "https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/reference/configuration.md"

func init() {
	defineFlags()
}

// defineFlags defines the flags on flag.CommandLine, each with its default: the tests define them
// again on a new one, as a flag set can't forget what it was given.
func defineFlags() {
	flag.StringVar(&configFile, "config_file", "config.yaml", "The configuration file, YAML or JSON: the names to keep, the providers, the discovery, the level of the log and the web server")
	flag.BoolVar(&live, "live", false, "Show the state in the terminal, updating, instead of the log")
	flag.BoolVar(&showVersion, "version", false, "Show the version, and exit")
	flag.Usage = usage
}

// usage lists the flags, as flag does, and tells where the rest is.
func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(flag.CommandLine.Output(), "\nEverything else is in the configuration file, whose keys are at:\n  %s\n", reference)
}

// unexpectedArgs is the error of the words left after the flags. There are none to give: flag
// stops at the first, so the flags after it would be left out without a word, as -config_file
// after "-live false".
func unexpectedArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected argument %q: the flags take no separate words, and a boolean one is turned off as -name=false", args[0])
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

	config, err := config.NewConfig(configFile)
	if err != nil {
		sugar.Fatalf("error reading config: %s", err)
	}
	if err := setLogLevel(config.LogLevel, level); err != nil {
		sugar.Fatalf("error in config: %s", err)
	}

	worker, err := ipv6ddns.NewWorker(sugar, config)
	if err != nil {
		sugar.Fatalf("error in config: %s", err)
	}

	// The plugins get the lifetime of the discovery: a family's own, when given, is the state's
	// to put in its place.
	plugins, err := config.Discovery.NewPlugins()
	if err != nil {
		sugar.Fatalf("can't create the plugins: %s", err)
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
			sugar.Fatalf("-live needs a terminal: %s", err)
		}
		closeTerminal = sync.OnceFunc(terminal.Close)
	}
	defer closeTerminal()

	err = worker.Start(ctx)
	if err != nil {
		closeTerminal()
		sugar.Fatalf("can't start worker: %s", err)
	}

	var servers []*http.Server
	if len(config.Webserver.Listen) > 0 {
		entries, err := listen.Parse(config.Webserver.Listen, webserverPort)
		if err != nil {
			closeTerminal()
			sugar.Fatalf("webserver.listen: %s", err)
		}
		listeners, err := listen.Listen(entries)
		if err != nil {
			closeTerminal()
			sugar.Fatalf("web server failed: %s", err)
		}
		for _, listener := range listeners {
			server := &http.Server{Handler: webHandler(worker), ReadHeaderTimeout: 10 * time.Second}
			servers = append(servers, server)
			go func() {
				sugar.Infof("Starting web server on %s", listener.Addr())
				if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
					closeTerminal()
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
		// The terminal takes the keys, Ctrl-C too: Run returns on them, and when ctx ends, as on
		// a SIGTERM, which is no key. The terminal is given back before the wait for the updates.
		terminal.Run(ctx, liveOutput)
		closeTerminal()
		stop()
	}
	<-ctx.Done()
	// The signals are the system's again: a second one ends the process without the wait.
	stop()

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
// hidden, as the server has no authentication. /healthz answers while the process runs, and its
// resolvers answer: 503 when one doesn't.
func webHandler(worker *ipv6ddns.Worker) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", statusHandler(worker))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if err := worker.Healthy(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(err.Error() + "\n"))
			return
		}
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

// webserverPort is that of the web server's entries that give none.
const webserverPort = config.DefaultWebserverPort

// setLogLevel gives the log the level of the configuration, info without one. With -live nothing
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
