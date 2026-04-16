package cosigner

import (
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

	return Config{
		NodeID:               cfg.Cosigner.NodeID,
		NATSURL:              cfg.NATS.URL,
		CoordinatorID:        cfg.Cosigner.Coordinator.ID,
		CoordinatorPublicKey: coordinatorKey,
		IdentityPrivateKey:   privateKey,
		DataDir:              cfg.Cosigner.DataDir,
		MaxActiveSessions:    64,
		PresenceInterval:     5 * time.Second,
		TickInterval:         100 * time.Millisecond,
	}, nil
}

func decodeHexKey(value, name string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return decoded, nil
}
