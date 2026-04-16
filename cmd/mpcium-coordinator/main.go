package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/fystack/mpcium/internal/coordinator"
	"github.com/nats-io/nats.go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	natsURL := flag.String("nats-url", envDefault("NATS_URL", nats.DefaultURL), "NATS server URL")
	coordinatorID := flag.String("coordinator-id", envDefault("COORDINATOR_ID", ""), "stable coordinator ID")
	privateKeyHex := flag.String("coordinator-private-key-hex", envDefault("COORDINATOR_PRIVATE_KEY_HEX", ""), "hex encoded Ed25519 private key")
	snapshotDir := flag.String("snapshot-dir", envDefault("COORDINATOR_SNAPSHOT_DIR", "coordinator-snapshots"), "directory for coordinator session snapshots")
	relayAvailable := flag.Bool("relay-available", envBoolDefault("COORDINATOR_RELAY_AVAILABLE", true), "whether relay is available for MQTT participants")
	defaultSessionTTLSec := flag.Int("default-session-ttl-sec", envIntDefault("COORDINATOR_DEFAULT_SESSION_TTL_SEC", 120), "default session TTL in seconds")
	tickInterval := flag.Duration("tick-interval", envDurationDefault("COORDINATOR_TICK_INTERVAL", time.Second), "session timeout scan interval")
	flag.Parse()

	if *coordinatorID == "" {
		return fmt.Errorf("coordinator-id is required")
	}
	if *privateKeyHex == "" {
		return fmt.Errorf("coordinator-private-key-hex is required")
	}

	signer, err := coordinator.NewEd25519SignerFromHex(*privateKeyHex)
	if err != nil {
		return err
	}

	nc, err := nats.Connect(*natsURL)
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	defer nc.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	snapshotStore := coordinator.NewAtomicFileSnapshotStore(*snapshotDir)
	sessionStore, err := coordinator.NewMemorySessionStore(ctx, snapshotStore)
	if err != nil {
		return fmt.Errorf("restore coordinator state: %w", err)
	}
	keyInfoStore := coordinator.NewMemoryKeyInfoStore()
	if err := coordinator.RestoreKeyInfoFromSnapshotStore(ctx, snapshotStore, keyInfoStore); err != nil {
		return fmt.Errorf("restore key info: %w", err)
	}
	_ = relayAvailable
	presence := coordinator.NewInMemoryPresenceView()
	coord, err := coordinator.NewCoordinator(coordinator.CoordinatorConfig{
		CoordinatorID:     *coordinatorID,
		Signer:            signer,
		EventVerifier:     coordinator.Ed25519SessionEventVerifier{},
		Store:             sessionStore,
		KeyInfoStore:      keyInfoStore,
		Presence:          presence,
		Controls:          coordinator.NewNATSControlPublisher(nc),
		Results:           coordinator.NewNATSResultPublisher(nc),
		DefaultSessionTTL: time.Duration(*defaultSessionTTLSec) * time.Second,
	})
	if err != nil {
		return err
	}

	runtime := coordinator.NewNATSRuntime(nc, coord, presence)
	if err := runtime.Start(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(*tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return runtime.Stop()
		case <-ticker.C:
			if _, err := coord.Tick(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "coordinator tick error:", err)
			}
		}
	}
}

func envDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBoolDefault(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDurationDefault(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envIntDefault(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
