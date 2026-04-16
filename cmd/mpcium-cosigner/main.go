package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/fystack/mpcium/internal/cosigner"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/urfave/cli/v3"
)

const cosignerConfigPath = "cosigner.config.yaml"

func main() {
	logger.Init(os.Getenv("ENVIRONMENT"), false)

	cmd := &cli.Command{
		Name:  "mpcium-cosigner",
		Usage: "Run MPC cosigner runtime",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to cosigner config file",
				Value:   cosignerConfigPath,
			},
		},
		Action: run,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		logger.Error("cosigner exited with error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, c *cli.Command) error {
	configPath := c.String("config")
	config.InitViperConfig(configPath)
	cfg, err := cosigner.LoadConfig()
	if err != nil {
		return err
	}

	return runCosigner(ctx, cfg)
}

func runCosigner(ctx context.Context, cfg cosigner.Config) error {
	runtime, err := cosigner.NewRuntime(cfg)
	if err != nil {
		return err
	}
	defer runtime.Close()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runtime.Run(ctx)
}
