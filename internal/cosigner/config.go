package cosigner

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type RelayProvider string

const (
	RelayProviderNATS RelayProvider = "nats"
	RelayProviderMQTT RelayProvider = "mqtt"
)

const (
	DefaultMaxActiveSessions = 5
	DefaultPresenceInterval  = 5 * time.Second
	DefaultTickInterval      = 100 * time.Millisecond
)

type Config struct {
	RelayProvider         RelayProvider
	NodeID                string
	NATS                  natsConfig
	MQTT                  mqttConfig
	OrchestratorID        string
	OrchestratorPublicKey []byte
	IdentityPrivateKey    []byte
	DataDir               string
	MaxActiveSessions     int
	PresenceInterval      time.Duration
	TickInterval          time.Duration
}

// Flat keys for compact config style.
type fileConfig struct {
	RelayProvider            RelayProvider `mapstructure:"relay_provider"`
	NATS                     natsConfig    `mapstructure:"nats"`
	MQTT                     mqttConfig    `mapstructure:"mqtt"`
	NodeID                   string        `mapstructure:"node_id"`
	DataDir                  string        `mapstructure:"data_dir"`
	OrchestratorID           string        `mapstructure:"orchestrator_id"`
	OrchestratorPublicKeyHex string        `mapstructure:"orchestrator_public_key_hex"`
	IdentityPrivateKeyHex    string        `mapstructure:"identity_private_key_hex"`
}

type natsConfig struct {
	URL      string     `mapstructure:"url"`
	Username string     `mapstructure:"username"`
	Password string     `mapstructure:"password"`
	TLS      *tlsConfig `mapstructure:"tls"`
}

type tlsConfig struct {
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	CACert     string `mapstructure:"ca_cert"`
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
	orchestratorKey, err := decodeHexKey(cfg.OrchestratorPublicKeyHex, "orchestrator public key")
	if err != nil {
		return Config{}, err
	}

	privateKey, err := decodeHexKey(cfg.IdentityPrivateKeyHex, "identity private key")
	if err != nil {
		return Config{}, err
	}

	runtimeCfg := Config{
		RelayProvider:         cfg.RelayProvider,
		NodeID:                cfg.NodeID,
		NATS:                  cfg.NATS,
		MQTT:                  cfg.MQTT,
		OrchestratorID:        cfg.OrchestratorID,
		OrchestratorPublicKey: orchestratorKey,
		IdentityPrivateKey:    privateKey,
		DataDir:               cfg.DataDir,
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
		cfg.MaxActiveSessions = DefaultMaxActiveSessions
	}
	if cfg.PresenceInterval <= 0 {
		cfg.PresenceInterval = DefaultPresenceInterval
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = DefaultTickInterval
	}

	cfg.NATS.URL = strings.TrimSpace(cfg.NATS.URL)
	cfg.NATS.Username = strings.TrimSpace(cfg.NATS.Username)
	cfg.NATS.Password = strings.TrimSpace(cfg.NATS.Password)
	if cfg.NATS.TLS != nil {
		cfg.NATS.TLS.ClientCert = strings.TrimSpace(cfg.NATS.TLS.ClientCert)
		cfg.NATS.TLS.ClientKey = strings.TrimSpace(cfg.NATS.TLS.ClientKey)
		cfg.NATS.TLS.CACert = strings.TrimSpace(cfg.NATS.TLS.CACert)
	}
}

func (cfg Config) Validate() error {
	if cfg.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}
	switch cfg.RelayProvider {
	case RelayProviderNATS:
		if cfg.NATS.URL == "" {
			return fmt.Errorf("nats.url is required for relay provider nats")
		}
		if cfg.NATS.TLS != nil {
			if cfg.NATS.TLS.ClientCert == "" {
				return fmt.Errorf("nats.tls.client_cert is required when nats.tls is set")
			}
			if cfg.NATS.TLS.ClientKey == "" {
				return fmt.Errorf("nats.tls.client_key is required when nats.tls is set")
			}
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
	if cfg.OrchestratorID == "" || len(cfg.OrchestratorPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("valid orchestrator key is required")
	}
	if len(cfg.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("valid identity private key is required")
	}
	if cfg.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	return nil
}
