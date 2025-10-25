package utils

import (
	"crypto/sha256"
	"io"
	"os"

	"github.com/rs/zerolog"
)

// GetMessageHash returns the SHA256 hash of the message
func GetMessageHash(msgBytes []byte) []byte {
	hash := sha256.Sum256(msgBytes)
	return hash[:]
}

// ZerologConsoleWriter returns a console writer for zerolog
func ZerologConsoleWriter() io.Writer {
	return zerolog.ConsoleWriter{Out: os.Stdout}
}
