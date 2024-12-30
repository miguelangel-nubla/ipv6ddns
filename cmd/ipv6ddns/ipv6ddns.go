package main

import (
	"flag"
	"log"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc/pkg/terminal"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var configFile string
var logLevel string
var stormDelay time.Duration
var lifetime time.Duration
var live bool

func init() {
	flag.StringVar(&configFile, "config_file", "config.json", "Path to the configuration file, default: config.json")
	flag.StringVar(&logLevel, "log_level", "info", "Logging level (debug, info, warn, error, fatal, panic) default: info")
	flag.DurationVar(&stormDelay, "storm_delay", 60*time.Second, "Time to allow for host discovery before updating the DDNS record")
	flag.DurationVar(&lifetime, "lifetime", 4*time.Hour, "Time to keep a discovered host entry after it has been last seen. Default: 4h")
	flag.BoolVar(&live, "live", false, "Show the currrent state live on the terminal, default: false")
}

func main() {
	flag.Parse()

	config := config.NewConfig(configFile)

	sugar := initializeLogger()
	rediscover := lifetime / 3

	worker := ipv6ddns.NewWorker(sugar, rediscover, lifetime, stormDelay, config)

	err := worker.Start()
	if err != nil {
		sugar.Fatalf("can't start worker: %s", err)
	}

	if live {
		liveOutput := make(chan string)
		go func() {
			for {
				liveOutput <- worker.PrettyPrint("")
				time.Sleep(1 * time.Second)
			}
		}()
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
