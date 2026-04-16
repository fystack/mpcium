package coordinator

import (
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type fileConfig struct {
	NATS        natsConfig        `mapstructure:"nats"`
	Coordinator coordinatorConfig `mapstructure:"coordinator"`
}

type natsConfig struct {
	URL string `mapstructure:"url"`
}

type coordinatorConfig struct {
	ID            string `mapstructure:"id"`
	PrivateKeyHex string `mapstructure:"private_key_hex"`
	SnapshotDir   string `mapstructure:"snapshot_dir"`
}

type RuntimeConfig struct {
	NATSURL           string
	ID                string
	PrivateKeyHex     string
	SnapshotDir       string
	DefaultSessionTTL time.Duration
	TickInterval      time.Duration
}

func (cfg RuntimeConfig) Validate() error {
	if cfg.NATSURL == "" {
		return fmt.Errorf("nats-url is required")
	}
	if cfg.ID == "" {
		return fmt.Errorf("coordinator-id is required")
	}
	if cfg.PrivateKeyHex == "" {
		return fmt.Errorf("coordinator-private-key-hex is required")
	}
	if cfg.SnapshotDir == "" {
		return fmt.Errorf("coordinator-snapshot-dir is required")
	}
	return nil
}

func LoadRuntimeConfig() (RuntimeConfig, error) {
	var cfg fileConfig
	if err := viper.Unmarshal(&cfg, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		return RuntimeConfig{}, fmt.Errorf("decode config: %w", err)
	}
	return cfg.Coordinator.runtimeConfig(cfg.NATS.URL), nil
}

func (cfg coordinatorConfig) runtimeConfig(natsURL string) RuntimeConfig {
	return RuntimeConfig{
		NATSURL:           natsURL,
		ID:                cfg.ID,
		PrivateKeyHex:     cfg.PrivateKeyHex,
		SnapshotDir:       cfg.SnapshotDir,
		DefaultSessionTTL: 120 * time.Second,
		TickInterval:      time.Second,
	}
}
