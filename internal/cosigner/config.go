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

const (
	DefaultMaxActiveSessions = 5
	DefaultPresenceInterval  = 5 * time.Second
	DefaultTickInterval      = 100 * time.Millisecond
)

type Config struct {
	ParticipantID         string
	NATS                  natsConfig
	OrchestratorID        string
	OrchestratorPublicKey []byte
	IdentityPrivateKey    []byte
	DataDir               string
	MaxActiveSessions     int
	PresenceInterval      time.Duration
	TickInterval          time.Duration
}

// EmbeddedFileConfig is the subset of config read from the parent process
// (e.g. mpcium) when the cosigner runtime is embedded in another binary.
// ParticipantID, IdentityPrivateKey, and the relay are supplied by the host.
type EmbeddedFileConfig struct {
	OrchestratorID           string        `mapstructure:"orchestrator_id"`
	OrchestratorPublicKeyHex string        `mapstructure:"orchestrator_public_key_hex"`
	DataDir                  string        `mapstructure:"data_dir"`
	MaxActiveSessions        int           `mapstructure:"max_active_sessions"`
	PresenceInterval         time.Duration `mapstructure:"presence_interval"`
	TickInterval             time.Duration `mapstructure:"tick_interval"`
}

// LoadEmbeddedConfig builds a Config from a viper subtree plus host-supplied
// participant identity. The relay is created separately and injected via
// NewRuntimeWithRelay.
func LoadEmbeddedConfig(sub *viper.Viper, participantID string, identityPrivateKey []byte) (Config, error) {
	if sub == nil {
		return Config{}, fmt.Errorf("cosigner config is required")
	}
	var fc EmbeddedFileConfig
	if err := sub.Unmarshal(&fc, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		return Config{}, fmt.Errorf("decode cosigner config: %w", err)
	}
	orchestratorKey, err := decodeHexKey(fc.OrchestratorPublicKeyHex, "orchestrator public key")
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		ParticipantID:         participantID,
		OrchestratorID:        fc.OrchestratorID,
		OrchestratorPublicKey: orchestratorKey,
		IdentityPrivateKey:    append([]byte(nil), identityPrivateKey...),
		DataDir:               fc.DataDir,
		MaxActiveSessions:     fc.MaxActiveSessions,
		PresenceInterval:      fc.PresenceInterval,
		TickInterval:          fc.TickInterval,
	}
	cfg.applyDefaults()
	if err := cfg.ValidateEmbedded(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ValidateEmbedded checks the fields required when the relay is host-supplied.
func (cfg Config) ValidateEmbedded() error {
	if cfg.ParticipantID == "" {
		return fmt.Errorf("participant_id is required")
	}
	if cfg.OrchestratorID == "" || len(cfg.OrchestratorPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("valid orchestrator key is required")
	}
	if len(cfg.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("valid identity private key is required")
	}
	if cfg.DataDir == "" {
		return fmt.Errorf("cosigner.data_dir is required")
	}
	return nil
}

// Flat keys for compact config style.
type fileConfig struct {
	NATS                     natsConfig `mapstructure:"nats"`
	ParticipantID            string     `mapstructure:"participant_id"`
	DataDir                  string     `mapstructure:"data_dir"`
	OrchestratorID           string     `mapstructure:"orchestrator_id"`
	OrchestratorPublicKeyHex string     `mapstructure:"orchestrator_public_key_hex"`
	IdentityPrivateKeyHex    string     `mapstructure:"identity_private_key_hex"`
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
		ParticipantID:         cfg.ParticipantID,
		NATS:                  cfg.NATS,
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
	if cfg.ParticipantID == "" {
		return fmt.Errorf("participant_id is required")
	}
	if cfg.NATS.URL == "" {
		return fmt.Errorf("nats.url is required")
	}
	if cfg.NATS.TLS != nil {
		if cfg.NATS.TLS.ClientCert == "" {
			return fmt.Errorf("nats.tls.client_cert is required when nats.tls is set")
		}
		if cfg.NATS.TLS.ClientKey == "" {
			return fmt.Errorf("nats.tls.client_key is required when nats.tls is set")
		}
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
