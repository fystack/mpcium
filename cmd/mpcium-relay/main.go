package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/fystack/mpcium/internal/relay"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/urfave/cli/v3"
)

const relayConfigPath = "relay.config.yaml"

func main() {
	logger.Init(os.Getenv("ENVIRONMENT"), false)

	cmd := &cli.Command{
		Name:  "mpcium-relay",
		Usage: "Run MQTT relay runtime",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to relay config file",
				Value:   relayConfigPath,
			},
		},
		Action: run,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		logger.Error("relay exited with error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, c *cli.Command) error {
	configPath := c.String("config")
	config.InitViperConfig(configPath)
	cfg, err := relay.LoadConfig()
	if err != nil {
		return err
	}

	runtime, err := relay.NewRuntime(cfg)
	if err != nil {
		return err
	}
	defer runtime.Close()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runtime.Run(ctx)
}
