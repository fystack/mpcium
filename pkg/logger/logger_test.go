package logger

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestInit_DoesNotPanic(t *testing.T) {
	// This test ensures Init can be called without panicking
	assert.NotPanics(t, func() {
		Init("test", false)
	})
}

func TestInit_SetsDebugLevel(t *testing.T) {
	Init("test", true)
	assert.Equal(t, zerolog.DebugLevel, zerolog.GlobalLevel())
}

func TestInit_SetsInfoLevel(t *testing.T) {
	Init("test", false)
	assert.Equal(t, zerolog.InfoLevel, zerolog.GlobalLevel())
}

func TestError_WithError(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()

	err := errors.New("test error")
	Error("test error message", err)

	output := buf.String()
	assert.Contains(t, output, "test error message")
	assert.Contains(t, output, "level\":\"error\"")
	assert.Contains(t, output, "test error")
}

func TestError_WithoutError(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()

	Error("test error message without error", nil)

	output := buf.String()
	assert.Contains(t, output, "test error message without error")
	assert.Contains(t, output, "level\":\"error\"")
}

func TestError_WithKeyValues(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()

	Error("test error with context", nil, "key1", "value1", "key2", 42)

	output := buf.String()
	assert.Contains(t, output, "test error with context")
	assert.Contains(t, output, "level\":\"error\"")
	assert.Contains(t, output, "key1")
	assert.Contains(t, output, "value1")
	assert.Contains(t, output, "key2")
	assert.Contains(t, output, "42")
}

func TestInfo_BasicMessage(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()

	Info("test info message")

	output := buf.String()
	assert.Contains(t, output, "test info message")
	assert.Contains(t, output, "level\":\"info\"")
}

func TestInfo_WithKeyValues(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()

	Info("test info with context", "user", "john", "action", "login")

	output := buf.String()
	assert.Contains(t, output, "test info with context")
	assert.Contains(t, output, "level\":\"info\"")
	assert.Contains(t, output, "user")
	assert.Contains(t, output, "john")
	assert.Contains(t, output, "action")
	assert.Contains(t, output, "login")
}

func TestDebug_BasicMessage(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	Debug("test debug message")

	output := buf.String()
	assert.Contains(t, output, "test debug message")
	assert.Contains(t, output, "level\":\"debug\"")
}

func TestWarn_BasicMessage(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()

	Warn("test warning message")

	output := buf.String()
	assert.Contains(t, output, "test warning message")
	assert.Contains(t, output, "level\":\"warn\"")
}

func TestInfof_FormattedMessage(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()

	Infof("formatted message: %s=%d", "count", 42)

	output := buf.String()
	assert.Contains(t, output, "formatted message: count=42")
	assert.Contains(t, output, "level\":\"info\"")
}

func TestError_PanicsOnOddKeyValues(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	Log = zerolog.New(&buf).With().Timestamp().Logger()

	assert.Panics(t, func() {
		Error("test error", nil, "odd_key") // odd number of key-value pairs
	})
}