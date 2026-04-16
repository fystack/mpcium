package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fystack/mpcium/internal/cosigner"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	nodeID := flag.String("node-id", envDefault("NODE_ID", ""), "local participant ID")
	natsURL := flag.String("nats-url", envDefault("NATS_URL", "nats://127.0.0.1:4222"), "NATS server URL")
	coordinatorID := flag.String("coordinator-id", envDefault("COORDINATOR_ID", ""), "coordinator ID")
	coordinatorPubHex := flag.String("coordinator-public-key-hex", envDefault("COORDINATOR_PUBLIC_KEY_HEX", ""), "coordinator Ed25519 public key hex")
	privateKeyHex := flag.String("identity-private-key-hex", envDefault("IDENTITY_PRIVATE_KEY_HEX", ""), "node Ed25519 private key hex")
	dataDir := flag.String("data-dir", envDefault("NODE_V1_DATA_DIR", "node-v1-data"), "node-v1 badger data directory")
	maxActive := flag.Int("max-active-sessions", envIntDefault("NODE_V1_MAX_ACTIVE_SESSIONS", 64), "maximum concurrent active sessions")
	presenceInterval := flag.Duration("presence-interval", envDurationDefault("NODE_V1_PRESENCE_INTERVAL", 5*time.Second), "presence heartbeat interval")
	tickInterval := flag.Duration("tick-interval", envDurationDefault("NODE_V1_TICK_INTERVAL", 100*time.Millisecond), "participant tick interval")
	flag.Parse()

	if *nodeID == "" || *coordinatorID == "" || *coordinatorPubHex == "" || *privateKeyHex == "" {
		return fmt.Errorf("node-id, coordinator-id, coordinator-public-key-hex, and identity-private-key-hex are required")
	}
	coordinatorKey, err := hex.DecodeString(*coordinatorPubHex)
	if err != nil {
		return fmt.Errorf("decode coordinator public key: %w", err)
	}
	privateKey, err := hex.DecodeString(*privateKeyHex)
	if err != nil {
		return fmt.Errorf("decode identity private key: %w", err)
	}

	runtime, err := cosigner.NewRuntime(cosigner.Config{
		NodeID:               *nodeID,
		NATSURL:              *natsURL,
		CoordinatorID:        *coordinatorID,
		CoordinatorPublicKey: coordinatorKey,
		IdentityPrivateKey:   privateKey,
		DataDir:              *dataDir,
		MaxActiveSessions:    *maxActive,
		PresenceInterval:     *presenceInterval,
		TickInterval:         *tickInterval,
	})
	if err != nil {
		return err
	}
	defer runtime.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runtime.Run(ctx)
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
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
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil {
		return fallback
	}
	return parsed
}
