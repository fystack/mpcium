package cosigner

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type Config struct {
	NodeID               string
	NATSURL              string
	CoordinatorID        string
	CoordinatorPublicKey []byte
	IdentityPrivateKey   []byte
	DataDir              string
	MaxActiveSessions    int
	PresenceInterval     time.Duration
	TickInterval         time.Duration
}

type fileConfig struct {
	NATS     natsConfig     `mapstructure:"nats"`
	Cosigner cosignerConfig `mapstructure:"cosigner"`
}

type natsConfig struct {
	URL string `mapstructure:"url"`
}

type cosignerConfig struct {
	NodeID      string            `mapstructure:"node_id"`
	DataDir     string            `mapstructure:"data_dir"`
	Coordinator coordinatorConfig `mapstructure:"coordinator"`
	Identity    identityConfig    `mapstructure:"identity"`
}

type coordinatorConfig struct {
	ID        string `mapstructure:"id"`
	PublicKey string `mapstructure:"public_key_hex"`
}

type identityConfig struct {
	PrivateKey string `mapstructure:"private_key_hex"`
}

func LoadConfig() (Config, error) {
	var cfg fileConfig
	if err := viper.Unmarshal(&cfg, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	coordinatorKey, err := decodeHexKey(cfg.Cosigner.Coordinator.PublicKey, "coordinator public key")
	if err != nil {
		return Config{}, err
	}

	privateKey, err := decodeHexKey(cfg.Cosigner.Identity.PrivateKey, "identity private key")
	if err != nil {
		return Config{}, err
	}

	runtimeCfg := Config{
		NodeID:               cfg.Cosigner.NodeID,
		NATSURL:              cfg.NATS.URL,
		CoordinatorID:        cfg.Cosigner.Coordinator.ID,
		CoordinatorPublicKey: coordinatorKey,
		IdentityPrivateKey:   privateKey,
		DataDir:              cfg.Cosigner.DataDir,
	}
	runtimeCfg.applyDefaults()
	if err := runtimeCfg.Validate(); err != nil {
		return Config{}, err
	}
	return runtimeCfg, nil
}

func decodeHexKey(value, name string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return decoded, nil
}

func (cfg *Config) applyDefaults() {
	if cfg.MaxActiveSessions <= 0 {
		cfg.MaxActiveSessions = 10
	}
	if cfg.PresenceInterval <= 0 {
		cfg.PresenceInterval = 5 * time.Second
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 100 * time.Millisecond
	}
}

func (cfg Config) Validate() error {
	if cfg.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}
	if cfg.NATSURL == "" {
		return fmt.Errorf("nats_url is required")
	}
	if cfg.CoordinatorID == "" || len(cfg.CoordinatorPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("valid coordinator key is required")
	}
	if len(cfg.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("valid identity private key is required")
	}
	if cfg.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	return nil
}
