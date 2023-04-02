package ipv6ddns

import (
	"flag"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/tree"

	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
	"github.com/miguelangel-nubla/ipv6disc/pkg/worker"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var configFile string
var logLevel string
var stormDelay time.Duration
var ttl time.Duration
var live bool

func init() {
	flag.StringVar(&configFile, "config_file", "config.json", "Path to the configuration file, default: config.json")
	flag.StringVar(&logLevel, "log_level", "info", "Logging level (debug, info, warn, error, fatal, panic) default: info")
	flag.DurationVar(&stormDelay, "storm_delay", 60*time.Second, "Time to allow for host discovery before updating the DDNS record")
	flag.DurationVar(&ttl, "ttl", 4*time.Hour, "Time to keep a discovered host entry in the table after it has been last seen. This is not the TTL of the DDNS record. Default: 4h")
	flag.BoolVar(&live, "live", false, "Show the currrent state live on the terminal, default: false")
}

func Start() {
	flag.Parse()

	startUpdater()
}

func startUpdater() {
	config := config.NewConfig(configFile)

	sugar := initializeLogger()

	liveOutput := make(chan string)

	table := worker.NewTable()
	err := worker.NewWorker(table, ttl, sugar).Start()
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	t := tree.NewTree()

	onUpdate := func(endpoint *tree.Endpoint, domainName string) error {
		sugar.Infof("endpoint %s starting update of: %s", endpoint.ID, domainName)

		endpoint.DomainsMutex.RLock()
		domain := endpoint.Domains[domainName]
		domain.HostsMutex.RLock()
		hostList := make([]string, 0, len(domain.Hosts))
		for _, host := range domain.Hosts {
			// Remove zone identifier from netip.Addr, zones strip prefixes
			hostList = append(hostList, netip.AddrFrom16(host.Address.As16()).String())
		}
		domain.HostsMutex.RUnlock()
		endpoint.DomainsMutex.RUnlock()

		err := endpoint.Service.Update(domainName, hostList)

		if err != nil {
			sugar.Errorf("endpoint %s error updating %s: %s", endpoint.ID, domainName, err)
		}

		return err
	}

	go func() {
		for {
			t.Update(config, table, stormDelay, onUpdate)

			if live {
				var result strings.Builder
				result.WriteString(t.PrettyPrint(4))
				result.WriteString(table.PrettyPrint(4))
				result.WriteString(config.PrettyPrint(4))
				liveOutput <- result.String()
			}

			time.Sleep(1 * time.Second)
		}
	}()

	if live {
		terminal.LiveOutput(liveOutput)
	} else {
		select {}
	}
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
