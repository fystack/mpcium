.PHONY: all build clean mpcium mpc test test-verbose test-coverage

BIN_DIR := bin

# Default target
all: build

# Build both binaries
build: mpcium mpc

# Install mpcium (builds and places it in $GOBIN or $GOPATH/bin)
mpcium:
	go install ./cmd/mpcium

# Install mpcium-cli
mpc:
	go install ./cmd/mpcium-cli

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test -v ./...

# Run tests with coverage report
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Wipe out manually built binaries if needed (not required by go install)
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html
