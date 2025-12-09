package config

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type AppConfig struct {
	Consul *ConsulConfig `mapstructure:"consul"`
	NATs   *NATsConfig   `mapstructure:"nats"`

	Environment    string `mapstructure:"environment"`
	BadgerPassword string `mapstructure:"badger_password"`
}

// Implement masking serializer AppConfig
func (c AppConfig) MarshalJSONMask() string {
	// clone app config
	c.BadgerPassword = strings.Repeat("*", len(c.BadgerPassword))
	c.Consul.Password = strings.Repeat("*", len(c.Consul.Password))
	c.Consul.Token = strings.Repeat("*", len(c.Consul.Token))
	c.NATs.Password = strings.Repeat("*", len(c.NATs.Password))

	bytes, err := json.Marshal(c)
	if err != nil {
		logger.Error("Failed to marshal app config", err)
	}
	return string(bytes)
}

type ConsulConfig struct {
	Address  string `mapstructure:"address"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Token    string `mapstructure:"token"`
}

type NATsConfig struct {
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

func InitViperConfig(configPath string) {
	if configPath != "" {
		// Use specific config file path
		viper.SetConfigFile(configPath)
	} else {
		// Use default behavior - search for config.yaml in common locations
		viper.SetConfigName("config")         // name of config file (without extension)
		viper.SetConfigType("yaml")           // REQUIRED if the config file does not have the extension in the name
		viper.AddConfigPath(".")              // optionally look for config in the working directory
		viper.AddConfigPath("/etc/mpcium/")   // look for config in /etc/mpcium/
		viper.AddConfigPath("$HOME/.mpcium/") // look for config in home directory
	}
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatal("Fatal error config file: ", err)
	}

	log.Println("Reading config file:", viper.ConfigFileUsed())
	log.Println("Initialized config successfully!")
}

func LoadConfig() *AppConfig {
	var config AppConfig
	decoderConfig := &mapstructure.DecoderConfig{
		Result:           &config,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		log.Fatal("Failed to create decoder", err)
	}

	if err := decoder.Decode(viper.AllSettings()); err != nil {
		log.Fatal("Failed to decode config", err)
	}

	if err := validateEnvironment(config.Environment); err != nil {
		log.Fatal("Config validation failed:", err)
	}

	return &config
}

func validateEnvironment(environment string) error {
	validEnvironments := []string{"production", "development"}

	for _, validEnv := range validEnvironments {
		if environment == validEnv {
			return nil
		}
	}

	return fmt.Errorf("invalid environment '%s'. Must be one of: %s", environment, strings.Join(validEnvironments, ", "))
}
