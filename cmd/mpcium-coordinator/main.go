package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fystack/mpcium/internal/coordinator"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
	"github.com/urfave/cli/v3"
)

const coordinatorConfigPath = "coordinator.config.yaml"

func main() {
	logger.Init(os.Getenv("ENVIRONMENT"), false)

	cmd := &cli.Command{
		Name:  "mpcium-coordinator",
		Usage: "Run MPC coordinator runtime",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to coordinator config file",
				Value:   coordinatorConfigPath,
			},
		},
		Action: run,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		logger.Error("coordinator exited with error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, c *cli.Command) error {
	configPath := c.String("config")
	config.InitViperConfig(configPath)

	cfg, err := coordinator.LoadRuntimeConfig()
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	signer, err := coordinator.NewEd25519SignerFromHex(cfg.PrivateKeyHex)
	if err != nil {
		return err
	}

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	defer nc.Close()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	snapshotStore := coordinator.NewAtomicFileSnapshotStore(cfg.SnapshotDir)
	sessionStore, err := coordinator.NewMemorySessionStore(ctx, snapshotStore)
	if err != nil {
		return fmt.Errorf("restore coordinator state: %w", err)
	}
	keyInfoStore := coordinator.NewMemoryKeyInfoStore()
	if err := coordinator.RestoreKeyInfoFromSnapshotStore(ctx, snapshotStore, keyInfoStore); err != nil {
		return fmt.Errorf("restore key info: %w", err)
	}

	presence := coordinator.NewInMemoryPresenceView()
	coord, err := coordinator.NewCoordinator(coordinator.CoordinatorConfig{
		CoordinatorID:     cfg.ID,
		Signer:            signer,
		EventVerifier:     coordinator.Ed25519SessionEventVerifier{},
		Store:             sessionStore,
		KeyInfoStore:      keyInfoStore,
		Presence:          presence,
		Controls:          coordinator.NewNATSControlPublisher(nc),
		Results:           coordinator.NewNATSResultPublisher(nc),
		DefaultSessionTTL: cfg.DefaultSessionTTL,
	})
	if err != nil {
		return err
	}

	natsRuntime := coordinator.NewNATSRuntime(nc, coord, presence)
	composite := coordinator.NewCompositeRuntime(natsRuntime)
	if cfg.GRPCEnabled {
		composite = coordinator.NewCompositeRuntime(
			natsRuntime,
			coordinator.NewGRPCRuntime(cfg.GRPCListenAddr, coord, cfg.GRPCPollInterval),
		)
	}

	if err := composite.Start(ctx); err != nil {
		return err
	}
	defer func() {
		if err := composite.Stop(); err != nil {
			logger.Error("stop coordinator runtime failed", err)
		}
	}()

	return runTickLoop(ctx, coord, cfg.TickInterval)
}

func runTickLoop(ctx context.Context, coord *coordinator.Coordinator, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := coord.Tick(ctx); err != nil {
				logger.Error("coordinator tick error", err)
			}
		}
	}
}
