package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
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
	flag.StringVar(&logLevel, "log_level", "info", "Logging level (debug, info, warn, error, fatal, panic) default: info")
	flag.DurationVar(&lifetime, "lifetime", 1*time.Hour, "Time to keep a discovered host entry after it has been last seen, default: 1h")
	flag.BoolVar(&live, "live", false, "Show the currrent state live on the terminal, default: false")
	flag.StringVar(&webserverListen, "webserver_listen", "", "Show the same live output to a browser, listening on this comma-separated list of addresses, host names and ports: 8053, 192.0.2.1, 192.0.2.1:8053, [2001:db8::1]:8053, myhost:8053 (no port: 80), default: disabled")
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Print(PrintVersion())
		os.Exit(0)
	}

	sugar := initializeLogger()

	config, err := config.NewConfig(configFile)
	if err != nil {
		sugar.Fatalf("error reading config: %s", err)
	}

	rediscover := lifetime / 3
	worker := ipv6ddns.NewWorker(sugar, rediscover, lifetime, config)

	for name, pCfg := range config.Discovery.Plugins {
		p, err := plugins.Create(pCfg.Type, name, pCfg.Params, lifetime)
		if err != nil {
			sugar.Fatalf("can't create plugin %s: %s", pCfg.Type, err)
		}

		worker.RegisterPlugin(p)
	}

	err = worker.Start()
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	if webserverListen != "" {
		addresses, err := parseListenList(webserverListen)
		if err != nil {
			sugar.Fatalf("webserver_listen: %s", err)
		}
		listeners, err := listenAll(addresses)
		if err != nil {
			sugar.Fatalf("web server failed: %s", err)
		}
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(wrapPrettyPrint(worker, "", true)))
		})
		for _, listener := range listeners {
			go func() {
				sugar.Infof("Starting web server on %s", listener.Addr())
				if err := http.Serve(listener, nil); err != nil {
					sugar.Fatalf("web server failed: %s", err)
				}
			}()
		}
	}

	if live {
		liveOutput := make(chan string)
		go func() {
			for {
				liveOutput <- wrapPrettyPrint(worker, "", false)
				time.Sleep(1 * time.Second)
			}
		}()
		terminal.LiveOutput(liveOutput)
	} else {
		select {}
	}
}

func wrapPrettyPrint(worker *ipv6ddns.Worker, prefix string, hideSensible bool) string {
	var result strings.Builder
	fmt.Fprint(&result, worker.PrettyPrint(prefix, hideSensible))
	fmt.Fprint(&result, prefix, PrintVersion())
	return result.String()
}

func initializeLogger() *zap.SugaredLogger {
	zapLevel, err := getLogLevel(logLevel)
	if err != nil {
		log.Fatalf("invalid log level: %s", logLevel)
	}

	if live {
		zapLevel = zapcore.FatalLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	logger := zap.Must(cfg.Build())
	defer logger.Sync()

	return logger.Sugar()
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

const defaultWebserverPort = "80"

// parseListenList turns a comma-separated list of addresses, host names and ports into host:port
// pairs. An empty host means all addresses; an entry with no port gets the default one.
func parseListenList(list string) ([]string, error) {
	var result []string
	seen := make(map[string]bool)
	for _, entry := range strings.Split(list, ",") {
		address, err := parseListenEntry(strings.TrimSpace(entry))
		if err != nil {
			return nil, err
		}
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	return result, nil
}

func parseListenEntry(entry string) (string, error) {
	if entry == "" {
		return "", fmt.Errorf("empty entry")
	}
	// A port alone. Before anything else: a bare number would otherwise be a host name.
	if _, err := strconv.Atoi(entry); err == nil {
		return checkedListenAddress("", entry, entry)
	}
	// An IP address with no port: an IPv6 one, bracketed or not, would confuse SplitHostPort.
	unbracketed := entry
	if strings.HasPrefix(entry, "[") && strings.HasSuffix(entry, "]") {
		unbracketed = entry[1 : len(entry)-1]
	}
	if ip, err := netip.ParseAddr(unbracketed); err == nil {
		return checkedListenAddress(ip.String(), defaultWebserverPort, entry)
	}
	if host, port, err := net.SplitHostPort(entry); err == nil {
		return checkedListenAddress(host, port, entry)
	}
	if strings.ContainsAny(entry, ":[]") {
		return "", fmt.Errorf("invalid entry %q", entry)
	}
	return checkedListenAddress(entry, defaultWebserverPort, entry)
}

func checkedListenAddress(host, port, entry string) (string, error) {
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port in %q", entry)
	}
	return net.JoinHostPort(host, port), nil
}

// listenAll opens every address, so a bad one stops the start instead of leaving part of the list
// up. A host name listens on each address it resolves to.
func listenAll(addresses []string) ([]net.Listener, error) {
	var listeners []net.Listener
	fail := func(err error) ([]net.Listener, error) {
		for _, listener := range listeners {
			listener.Close()
		}
		return nil, err
	}
	seen := make(map[string]bool)
	for _, address := range addresses {
		expanded, err := expandHostName(address)
		if err != nil {
			return fail(err)
		}
		for _, a := range expanded {
			if seen[a] {
				continue
			}
			seen[a] = true
			listener, err := net.Listen("tcp", a)
			if err != nil {
				return fail(err)
			}
			listeners = append(listeners, listener)
		}
	}
	return listeners, nil
}

func expandHostName(address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); host == "" || err == nil {
		return []string{address}, nil
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, ip := range ips {
		result = append(result, net.JoinHostPort(ip, port))
	}
	return result, nil
}
