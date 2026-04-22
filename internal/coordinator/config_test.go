package coordinator

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestLoadRuntimeConfigDecodesGRPCConfig(t *testing.T) {
	t.Cleanup(viper.Reset)
	configPath := writeCoordinatorConfig(t, `
nats:
  url: nats://127.0.0.1:4222
grpc:
  enabled: true
  listen_addr: 127.0.0.1:50051
  poll_interval: 250ms
coordinator:
  id: coordinator-01
  private_key_hex: abc123
  snapshot_dir: coordinator-snapshots
`)
	viper.SetConfigFile(configPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.GRPCEnabled || cfg.GRPCListenAddr != "127.0.0.1:50051" || cfg.GRPCPollInterval != 250*time.Millisecond {
		t.Fatalf("unexpected grpc config: %+v", cfg)
	}
}

func TestLoadRuntimeConfigRejectsInvalidGRPCPollInterval(t *testing.T) {
	t.Cleanup(viper.Reset)
	configPath := writeCoordinatorConfig(t, `
nats:
  url: nats://127.0.0.1:4222
grpc:
  enabled: true
  listen_addr: 127.0.0.1:50051
  poll_interval: nope
coordinator:
  id: coordinator-01
  private_key_hex: abc123
  snapshot_dir: coordinator-snapshots
`)
	viper.SetConfigFile(configPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatalf("expected invalid duration error")
	}
}

func TestRuntimeConfigValidateUsesConfigKeyNames(t *testing.T) {
	err := RuntimeConfig{}.Validate()
	if err == nil || err.Error() != "nats.url is required" {
		t.Fatalf("Validate() error = %v", err)
	}
}

func writeCoordinatorConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "coordinator.config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
