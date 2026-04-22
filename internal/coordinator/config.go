package coordinator

import (
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

const (
	DefaultSessionTTL   = 120 * time.Second
	DefaultTickInterval = time.Second
)

type fileConfig struct {
	NATS        natsConfig        `mapstructure:"nats"`
	GRPC        grpcConfig        `mapstructure:"grpc"`
	Coordinator coordinatorConfig `mapstructure:"coordinator"`
}

type natsConfig struct {
	URL string `mapstructure:"url"`
}

type grpcConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	ListenAddr   string        `mapstructure:"listen_addr"`
	PollInterval time.Duration `mapstructure:"poll_interval"`
}

type coordinatorConfig struct {
	ID            string `mapstructure:"id"`
	PrivateKeyHex string `mapstructure:"private_key_hex"`
	SnapshotDir   string `mapstructure:"snapshot_dir"`
}

type RuntimeConfig struct {
	NATSURL           string
	GRPCEnabled       bool
	GRPCListenAddr    string
	GRPCPollInterval  time.Duration
	ID                string
	PrivateKeyHex     string
	SnapshotDir       string
	DefaultSessionTTL time.Duration
	TickInterval      time.Duration
}

func (cfg RuntimeConfig) Validate() error {
	if cfg.NATSURL == "" {
		return fmt.Errorf("nats.url is required")
	}
	if cfg.ID == "" {
		return fmt.Errorf("coordinator.id is required")
	}
	if cfg.PrivateKeyHex == "" {
		return fmt.Errorf("coordinator.private_key_hex is required")
	}
	if cfg.SnapshotDir == "" {
		return fmt.Errorf("coordinator.snapshot_dir is required")
	}
	if cfg.GRPCEnabled && cfg.GRPCListenAddr == "" {
		return fmt.Errorf("grpc.listen_addr is required when grpc is enabled")
	}
	return nil
}

func LoadRuntimeConfig() (RuntimeConfig, error) {
	var cfg fileConfig
	if err := viper.Unmarshal(&cfg, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		return RuntimeConfig{}, fmt.Errorf("decode config: %w", err)
	}
	return cfg.Coordinator.runtimeConfig(cfg.NATS.URL, cfg.GRPC), nil
}

func (cfg coordinatorConfig) runtimeConfig(natsURL string, grpc grpcConfig) RuntimeConfig {
	pollInterval := 200 * time.Millisecond
	if grpc.PollInterval > 0 {
		pollInterval = grpc.PollInterval
	}
	return RuntimeConfig{
		NATSURL:           natsURL,
		GRPCEnabled:       grpc.Enabled,
		GRPCListenAddr:    grpc.ListenAddr,
		GRPCPollInterval:  pollInterval,
		ID:                cfg.ID,
		PrivateKeyHex:     cfg.PrivateKeyHex,
		SnapshotDir:       cfg.SnapshotDir,
		DefaultSessionTTL: DefaultSessionTTL,
		TickInterval:      DefaultTickInterval,
	}
}

type CoordinatorConfig struct {
	CoordinatorID     string
	Signer            Signer
	EventVerifier     SessionEventVerifier
	Store             *MemorySessionStore
	KeyInfoStore      *MemoryKeyInfoStore
	Presence          PresenceView
	Controls          ControlPublisher
	Results           ResultPublisher
	DefaultSessionTTL time.Duration
	Now               func() time.Time
}

func applyDefaults(cfg CoordinatorConfig) CoordinatorConfig {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.DefaultSessionTTL <= 0 {
		cfg.DefaultSessionTTL = 120 * time.Second
	}
	return cfg
}

func (cfg CoordinatorConfig) Validate() error {
	if cfg.CoordinatorID == "" {
		return fmt.Errorf("coordinator ID is required")
	}
	if cfg.Signer == nil {
		return fmt.Errorf("signer is required")
	}
	if cfg.Store == nil {
		return fmt.Errorf("session store is required")
	}
	if cfg.Presence == nil {
		return fmt.Errorf("presence view is required")
	}
	if cfg.Controls == nil {
		return fmt.Errorf("control publisher is required")
	}
	if cfg.Results == nil {
		return fmt.Errorf("result publisher is required")
	}
	return nil
}
