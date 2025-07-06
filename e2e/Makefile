.PHONY: test setup clean deps

# Default target
test: deps setup
	@echo "Running E2E tests..."
	go test -v -timeout=10m ./...

# Setup test environment
setup:
	@echo "🔧 Setting up test environment..."
	@if ! command -v mpcium >/dev/null 2>&1; then \
		echo "❌ mpcium binary not found in PATH. Please run 'make' in the root directory first."; \
		exit 1; \
	fi
	@if ! command -v mpcium-cli >/dev/null 2>&1; then \
		echo "❌ mpcium-cli binary not found in PATH. Please run 'make' in the root directory first."; \
		exit 1; \
	fi
	@echo "✅ Binaries found"

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	go mod tidy
	go mod download

# Clean up test artifacts
clean:
	@echo "🧹 Cleaning up test artifacts..."
	rm -rf test_db/
	rm -rf test_node*/
	rm -f test_event_initiator.*
	rm -rf logs 
	rm -f config.test.yaml
	docker compose -f docker-compose.test.yaml down --remove-orphans 2>/dev/null || true

# Quick test (skip setup)
test-quick:
	@echo "⚡ Running quick E2E tests..."
	go test -v -timeout=10m ./...

# Help
help:
	@echo "Available targets:"
	@echo "  test         - Run E2E tests with full setup"
	@echo "  test-quick   - Run E2E tests without setup"
	@echo "  setup        - Setup test environment"
	@echo "  deps         - Install dependencies"
	@echo "  clean        - Clean up test artifacts"
	@echo "  help         - Show this help message" 
