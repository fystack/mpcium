.PHONY: all build clean mpcium mpc install reset test test-verbose test-coverage e2e-test e2e-clean cleanup-test-env

BIN_DIR := bin

# Detect OS
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME_S),Linux)
	DETECTED_OS := linux
	INSTALL_DIR := /usr/local/bin
	SUDO := sudo
	RM := rm -f
endif
ifeq ($(UNAME_S),Darwin)
	DETECTED_OS := darwin
	INSTALL_DIR := /usr/local/bin
	SUDO := sudo
	RM := rm -f
endif
ifeq ($(UNAME_S),Windows)
	DETECTED_OS := windows
	INSTALL_DIR := $(USERPROFILE)/bin
	SUDO :=
	RM := del /Q
endif
# Fallback for Windows (Git Bash, MSYS2, etc.)
ifeq ($(OS),Windows_NT)
	DETECTED_OS := windows
	INSTALL_DIR := $(HOME)/bin
	SUDO :=
	RM := rm -f
endif

# Detect architecture
UNAME_M := $(shell uname -m 2>/dev/null || echo amd64)
ifeq ($(UNAME_M),x86_64)
	GOARCH := amd64
endif
ifeq ($(UNAME_M),amd64)
	GOARCH := amd64
endif
ifeq ($(UNAME_M),arm64)
	GOARCH := arm64
endif
ifeq ($(UNAME_M),aarch64)
	GOARCH := arm64
endif

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

# Install binaries (auto-detects OS and architecture)
install:
	@echo "Detected OS: $(DETECTED_OS)"
	@echo "Building and installing mpcium binaries..."
ifeq ($(DETECTED_OS),windows)
	@echo "Building for Windows..."
	GOOS=windows GOARCH=$(GOARCH) go build -o $(BIN_DIR)/mpcium.exe ./cmd/mpcium
	GOOS=windows GOARCH=$(GOARCH) go build -o $(BIN_DIR)/mpcium-cli.exe ./cmd/mpcium-cli
	@echo "Binaries built in $(BIN_DIR)/"
	@echo "Please add $(BIN_DIR) to your PATH or manually copy the binaries to a location in your PATH"
else
	@mkdir -p /tmp/mpcium-install
	GOOS=$(DETECTED_OS) GOARCH=$(GOARCH) go build -o /tmp/mpcium-install/mpcium ./cmd/mpcium
	GOOS=$(DETECTED_OS) GOARCH=$(GOARCH) go build -o /tmp/mpcium-install/mpcium-cli ./cmd/mpcium-cli
	$(SUDO) install -m 755 /tmp/mpcium-install/mpcium $(INSTALL_DIR)/
	$(SUDO) install -m 755 /tmp/mpcium-install/mpcium-cli $(INSTALL_DIR)/
	rm -rf /tmp/mpcium-install
	@echo "Successfully installed mpcium and mpcium-cli to $(INSTALL_DIR)/"
endif

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

# Run E2E integration tests
e2e-test: build
	@echo "Running E2E integration tests..."
	cd e2e && make test

# Run E2E tests with coverage
e2e-test-coverage: build
	@echo "Running E2E integration tests with coverage..."
	cd e2e && make test-coverage

# Clean up E2E test artifacts
e2e-clean:
	@echo "Cleaning up E2E test artifacts..."
	cd e2e && make clean

# Comprehensive cleanup of test environment (kills processes, removes artifacts)
cleanup-test-env:
	@echo "Performing comprehensive test environment cleanup..."
	cd e2e && ./cleanup_test_env.sh

# Run all tests (unit + E2E)
test-all: test e2e-test

# Wipe out manually built binaries if needed (not required by go install)
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

# Full clean (including E2E artifacts)
clean-all: clean e2e-clean

# Reset the entire local environment
reset:
	@echo "Removing project artifacts..."
	rm -rf $(BIN_DIR)
	rm -rf node0 node1 node2
	rm -rf event_initiator.identity.json event_initiator.key event_initiator.key.age
	rm -rf config.yaml peers.json
	rm -f coverage.out coverage.html
	@echo "Cleaning E2E artifacts..."
	- $(MAKE) e2e-clean || true
	@echo "Reset completed."
