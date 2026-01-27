package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/mikrotik"
	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var showVersion bool
var configFile string
var logLevel string
var lifetime time.Duration
var live bool
var webserverPort int

func init() {
	flag.BoolVar(&showVersion, "version", false, "Show the current version")
	flag.StringVar(&configFile, "config_file", "config.yaml", "Path to the configuration file, default: config.yaml")
	flag.StringVar(&logLevel, "log_level", "info", "Logging level (debug, info, warn, error, fatal, panic) default: info")
	flag.DurationVar(&lifetime, "lifetime", 1*time.Hour, "Time to keep a discovered host entry after it has been last seen, default: 1h")
	flag.BoolVar(&live, "live", false, "Show the currrent state live on the terminal, default: false")
	flag.IntVar(&webserverPort, "webserver_port", 0, "If port specified you can connect to this port to view the same live output from a browser, default: disabled")
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
		p, err := plugins.Create(pCfg.Type, pCfg.Params, lifetime)
		if err != nil {
			sugar.Fatalf("can't create plugin %s: %s", pCfg.Type, err)
		}

		// Wrap the plugin to override the name with the instance name from config
		p = &PluginInstance{
			Plugin: p,
			name:   name,
		}

		worker.RegisterPlugin(p)
	}

	err = worker.Start()
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	if webserverPort > 0 {
		go func() {
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(wrapPrettyPrint(worker, "", true)))
			})
			sugar.Infof("Starting web server on port %d", webserverPort)
			if err := http.ListenAndServe(fmt.Sprintf(":%d", webserverPort), nil); err != nil {
				sugar.Fatalf("web server failed: %s", err)
			}
		}()
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

type PluginInstance struct {
	ipv6disc.Plugin
	name string
}

func (p *PluginInstance) Name() string {
	return p.name
}
