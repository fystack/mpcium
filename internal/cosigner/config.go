package cosigner

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type RelayProvider string

const (
	RelayProviderNATS RelayProvider = "nats"
	RelayProviderMQTT RelayProvider = "mqtt"
)

type Config struct {
	RelayProvider        RelayProvider
	NodeID               string
	NATSURL              string
	MQTT                 mqttConfig
	CoordinatorID        string
	CoordinatorPublicKey []byte
	IdentityPrivateKey   []byte
	DataDir              string
	MaxActiveSessions    int
	PresenceInterval     time.Duration
	TickInterval         time.Duration
}

// Flat keys for compact config style.
type fileConfig struct {
	RelayProvider           RelayProvider `mapstructure:"relay_provider"`
	NATSURL                 string        `mapstructure:"nats_url"`
	MQTT                    mqttConfig    `mapstructure:"mqtt"`
	NodeID                  string        `mapstructure:"node_id"`
	DataDir                 string        `mapstructure:"data_dir"`
	CoordinatorID           string        `mapstructure:"coordinator_id"`
	CoordinatorPublicKeyHex string        `mapstructure:"coordinator_public_key_hex"`
	IdentityPrivateKeyHex   string        `mapstructure:"identity_private_key_hex"`
}

type mqttConfig struct {
	Broker   string `mapstructure:"broker"`
	ClientID string `mapstructure:"client_id"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

func LoadConfig() (Config, error) {
	var cfg fileConfig
	if err := viper.Unmarshal(&cfg, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	coordinatorKey, err := decodeHexKey(cfg.CoordinatorPublicKeyHex, "coordinator public key")
	if err != nil {
		return Config{}, err
	}

	privateKey, err := decodeHexKey(cfg.IdentityPrivateKeyHex, "identity private key")
	if err != nil {
		return Config{}, err
	}

	runtimeCfg := Config{
		RelayProvider:        cfg.RelayProvider,
		NodeID:               cfg.NodeID,
		NATSURL:              cfg.NATSURL,
		MQTT:                 cfg.MQTT,
		CoordinatorID:        cfg.CoordinatorID,
		CoordinatorPublicKey: coordinatorKey,
		IdentityPrivateKey:   privateKey,
		DataDir:              cfg.DataDir,
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
	if cfg.RelayProvider == "" {
		cfg.RelayProvider = RelayProviderNATS
	}
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
	switch cfg.RelayProvider {
	case RelayProviderNATS:
		if cfg.NATSURL == "" {
			return fmt.Errorf("nats_url is required for relay provider nats")
		}
	case RelayProviderMQTT:
		if cfg.MQTT.Broker == "" {
			return fmt.Errorf("mqtt.broker is required for relay provider mqtt")
		}
		if cfg.MQTT.ClientID == "" {
			return fmt.Errorf("mqtt.client_id is required for relay provider mqtt")
		}
	default:
		return fmt.Errorf("unsupported relay provider: %s", cfg.RelayProvider)
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
