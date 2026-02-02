package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppConfig_MarshalJSONMask(t *testing.T) {
	config := AppConfig{
		NATs: &NATsConfig{
			URL:      "nats://localhost:4222",
			Username: "nats_user",
			Password: "nats_pass",
		},
		BadgerPassword: "badger_secret",
	}

	masked := config.MarshalJSONMask()

	// Verify that sensitive data is masked
	assert.Contains(t, masked, "nats_user")             // Username should not be masked
	assert.Contains(t, masked, "nats://localhost:4222") // URL should not be masked

	// Verify that passwords are masked
	assert.NotContains(t, masked, "nats_pass")
	assert.NotContains(t, masked, "badger_secret")

	// Check that asterisks are present for masked fields
	assert.Contains(t, masked, strings.Repeat("*", len("nats_pass")))
	assert.Contains(t, masked, strings.Repeat("*", len("badger_secret")))
}

func TestAppConfig_MarshalJSONMask_EmptyPasswords(t *testing.T) {
	config := AppConfig{
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
	assert.Contains(t, masked, "nats_user")
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
		NATs: &NATsConfig{}, // Initialize with empty struct instead of nil
	}

	// Should handle default/empty values gracefully
	masked := config.MarshalJSONMask()
	assert.NotEmpty(t, masked)
}

func TestAppConfig_PartialConfig(t *testing.T) {
	config := AppConfig{
		NATs:           &NATsConfig{}, // Initialize to avoid nil pointer
		BadgerPassword: "test",
	}

	// Should handle partial configuration
	masked := config.MarshalJSONMask()
	assert.NotContains(t, masked, "test")
	assert.Contains(t, masked, "****") // masked badger password
}

func TestValidateEnvironment(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		wantErr     bool
	}{
		{
			name:        "valid production environment",
			environment: "production",
			wantErr:     false,
		},
		{
			name:        "valid development environment",
			environment: "development",
			wantErr:     false,
		},
		{
			name:        "invalid environment",
			environment: "staging",
			wantErr:     true,
		},
		{
			name:        "empty environment",
			environment: "",
			wantErr:     true,
		},
		{
			name:        "case sensitive - Production",
			environment: "Production",
			wantErr:     true,
		},
		{
			name:        "case sensitive - PRODUCTION",
			environment: "PRODUCTION",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEnvironment(tt.environment)
			if tt.wantErr {
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), "invalid environment")
					assert.Contains(t, err.Error(), "production, development")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
