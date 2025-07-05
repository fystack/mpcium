package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppConfig_MarshalJSONMask(t *testing.T) {
	config := AppConfig{
		Consul: &ConsulConfig{
			Address:  "localhost:8500",
			Username: "admin",
			Password: "secret123",
			Token:    "token456",
		},
		NATs: &NATsConfig{
			URL:      "nats://localhost:4222",
			Username: "nats_user",
			Password: "nats_pass",
		},
		BadgerPassword: "badger_secret",
	}

	masked := config.MarshalJSONMask()

	// Verify that sensitive data is masked
	assert.Contains(t, masked, "localhost:8500") // Address should not be masked
	assert.Contains(t, masked, "admin")          // Username should not be masked
	assert.Contains(t, masked, "nats_user")      // Username should not be masked
	assert.Contains(t, masked, "nats://localhost:4222") // URL should not be masked

	// Verify that passwords are masked
	assert.NotContains(t, masked, "secret123")
	assert.NotContains(t, masked, "token456")
	assert.NotContains(t, masked, "nats_pass")
	assert.NotContains(t, masked, "badger_secret")

	// Check that asterisks are present for masked fields
	assert.Contains(t, masked, strings.Repeat("*", len("secret123")))
	assert.Contains(t, masked, strings.Repeat("*", len("token456")))
	assert.Contains(t, masked, strings.Repeat("*", len("nats_pass")))
	assert.Contains(t, masked, strings.Repeat("*", len("badger_secret")))
}

func TestAppConfig_MarshalJSONMask_EmptyPasswords(t *testing.T) {
	config := AppConfig{
		Consul: &ConsulConfig{
			Address:  "localhost:8500",
			Username: "admin",
			Password: "",
			Token:    "",
		},
		NATs: &NATsConfig{
			URL:      "nats://localhost:4222",
			Username: "nats_user",
			Password: "",
		},
		BadgerPassword: "",
	}

	masked := config.MarshalJSONMask()

	// Should not crash with empty passwords
	assert.NotEmpty(t, masked)
	assert.Contains(t, masked, "localhost:8500")
	assert.Contains(t, masked, "admin")
	assert.Contains(t, masked, "nats_user")
}

func TestConsulConfig(t *testing.T) {
	config := ConsulConfig{
		Address:  "consul.example.com:8500",
		Username: "consul_user",
		Password: "consul_pass",
		Token:    "consul_token",
	}

	assert.Equal(t, "consul.example.com:8500", config.Address)
	assert.Equal(t, "consul_user", config.Username)
	assert.Equal(t, "consul_pass", config.Password)
	assert.Equal(t, "consul_token", config.Token)
}

func TestNATsConfig(t *testing.T) {
	config := NATsConfig{
		URL:      "nats://nats.example.com:4222",
		Username: "nats_user",
		Password: "nats_pass",
	}

	assert.Equal(t, "nats://nats.example.com:4222", config.URL)
	assert.Equal(t, "nats_user", config.Username)
	assert.Equal(t, "nats_pass", config.Password)
}

func TestAppConfig_DefaultValues(t *testing.T) {
	config := AppConfig{
		Consul: &ConsulConfig{}, // Initialize with empty struct instead of nil
		NATs:   &NATsConfig{},   // Initialize with empty struct instead of nil
	}

	// Should handle default/empty values gracefully
	masked := config.MarshalJSONMask()
	assert.NotEmpty(t, masked)
}

func TestAppConfig_PartialConfig(t *testing.T) {
	config := AppConfig{
		Consul: &ConsulConfig{
			Address: "localhost:8500",
		},
		NATs:           &NATsConfig{}, // Initialize to avoid nil pointer
		BadgerPassword: "test",
	}

	// Should handle partial configuration
	masked := config.MarshalJSONMask()
	assert.Contains(t, masked, "localhost:8500")
	assert.NotContains(t, masked, "test")
	assert.Contains(t, masked, "****") // masked badger password
}