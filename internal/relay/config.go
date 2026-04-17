package relay

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type RuntimeConfig struct {
	NATS     NATSConfig     `mapstructure:"nats"`
	MQTT     MQTTConfig     `mapstructure:"relay.mqtt"`
	Bridge   BridgeConfig   `mapstructure:"relay.bridge"`
	Presence PresenceConfig `mapstructure:"relay.presence"`
}

type NATSConfig struct {
	URL      string     `mapstructure:"url"`
	Username string     `mapstructure:"username"`
	Password string     `mapstructure:"password"`
	TLS      *TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	CACert     string `mapstructure:"ca_cert"`
}

type MQTTConfig struct {
	ListenAddress        string `mapstructure:"listen_address"`
	UsernamePasswordFile string `mapstructure:"username_password_file"`
}

type BridgeConfig struct {
	NATSPrefix   string `mapstructure:"nats_prefix"`
	MQTTPrefix   string `mapstructure:"mqtt_prefix"`
	MQTTQoS      byte   `mapstructure:"mqtt_qos"`
	OriginHeader string `mapstructure:"origin_header"`
}

type PresenceConfig struct {
	EmitConnectDisconnect bool `mapstructure:"emit_connect_disconnect"`
}

func LoadConfig() (RuntimeConfig, error) {
	setDefaults()

	var cfg RuntimeConfig
	if err := viper.Unmarshal(&cfg); err != nil {
		return RuntimeConfig{}, fmt.Errorf("decode relay config: %w", err)
	}

	cfg.normalize()

	if err := cfg.Validate(); err != nil {
		return RuntimeConfig{}, err
	}

	return cfg, nil
}

func setDefaults() {
	viper.SetDefault("relay.mqtt.listen_address", ":1883")
	viper.SetDefault("relay.bridge.nats_prefix", "mpc.v1")
	viper.SetDefault("relay.bridge.mqtt_prefix", "mpc/v1")
	viper.SetDefault("relay.bridge.mqtt_qos", 1)
	viper.SetDefault("relay.bridge.origin_header", "X-MPCIUM-Relay-Origin")
	viper.SetDefault("relay.presence.emit_connect_disconnect", true)
}

func (cfg *RuntimeConfig) normalize() {
	cfg.NATS.URL = strings.TrimSpace(cfg.NATS.URL)
	cfg.NATS.Username = strings.TrimSpace(cfg.NATS.Username)
	cfg.NATS.Password = strings.TrimSpace(cfg.NATS.Password)

	if cfg.NATS.TLS != nil {
		cfg.NATS.TLS.ClientCert = strings.TrimSpace(cfg.NATS.TLS.ClientCert)
		cfg.NATS.TLS.ClientKey = strings.TrimSpace(cfg.NATS.TLS.ClientKey)
		cfg.NATS.TLS.CACert = strings.TrimSpace(cfg.NATS.TLS.CACert)
	}

	cfg.MQTT.ListenAddress = strings.TrimSpace(cfg.MQTT.ListenAddress)
	cfg.MQTT.UsernamePasswordFile = strings.TrimSpace(cfg.MQTT.UsernamePasswordFile)

	cfg.Bridge.NATSPrefix = strings.TrimSpace(cfg.Bridge.NATSPrefix)
	cfg.Bridge.MQTTPrefix = strings.TrimSpace(cfg.Bridge.MQTTPrefix)
	cfg.Bridge.OriginHeader = strings.TrimSpace(cfg.Bridge.OriginHeader)
}

func (cfg RuntimeConfig) Validate() error {
	if cfg.NATS.URL == "" {
		return fmt.Errorf("nats.url is required")
	}
	if cfg.MQTT.ListenAddress == "" {
		return fmt.Errorf("relay.mqtt.listen_address is required")
	}
	if cfg.MQTT.UsernamePasswordFile == "" {
		return fmt.Errorf("relay.mqtt.username_password_file is required")
	}
	if cfg.Bridge.NATSPrefix == "" {
		return fmt.Errorf("relay.bridge.nats_prefix is required")
	}
	if cfg.Bridge.MQTTPrefix == "" {
		return fmt.Errorf("relay.bridge.mqtt_prefix is required")
	}
	if cfg.Bridge.OriginHeader == "" {
		return fmt.Errorf("relay.bridge.origin_header is required")
	}
	if cfg.Bridge.MQTTQoS > 2 {
		return fmt.Errorf("relay.bridge.mqtt_qos must be 0, 1, or 2")
	}
	if cfg.NATS.TLS != nil {
		if cfg.NATS.TLS.ClientCert == "" {
			return fmt.Errorf("nats.tls.client_cert is required when nats.tls is set")
		}
		if cfg.NATS.TLS.ClientKey == "" {
			return fmt.Errorf("nats.tls.client_key is required when nats.tls is set")
		}
	}
	return nil
}
