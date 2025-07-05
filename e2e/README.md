# E2E Integration Tests

This directory contains end-to-end integration tests for the MPCIUM multi-party computation system.

## Overview

The E2E tests verify that the complete MPC system works correctly by:

1. **Infrastructure Setup**: Using testcontainers to spin up isolated NATS and Consul instances
2. **Node Setup**: Creating 3 test nodes with separate identities and configurations
3. **Key Generation**: Testing concurrent key generation for multiple wallets
4. **Consistency Verification**: Ensuring all generated keys are properly stored across all nodes
5. **Cleanup**: Removing all test artifacts and containers

## Prerequisites

Before running the tests, ensure you have:

- **Docker** installed and running
- **Go** 1.23+ installed
- **mpcium** and **mpcium-cli** binaries built (run `make` in the root directory)

## Running Tests

### Quick Start

```bash
# Run all E2E tests
make test

# Run tests with coverage report
make test-coverage

# Clean up test artifacts
make clean
```

### Manual Steps

1. **Build the binaries** (from root directory):
   ```bash
   make
   ```

2. **Run the E2E tests**:
   ```bash
   cd e2e
   make test
   ```

## Test Structure

### Files

- `keygen_test.go` - Main test file with the E2E test suite
- `docker-compose.test.yaml` - Test infrastructure configuration
- `config.test.yaml` - Test node configuration template
- `setup_test_identities.sh` - Script to set up test node identities
- `Makefile` - Build and test automation

### Test Flow

1. **Setup Infrastructure**
   - Starts NATS (port 4223) and Consul (port 8501) containers
   - Creates service clients for test coordination

2. **Setup Test Nodes**
   - Creates 3 test nodes (`test_node0`, `test_node1`, `test_node2`)
   - Generates unique identities for each node
   - Configures separate database paths (`./test_db/`)
   - Registers peers in Consul

3. **Start MPC Nodes**
   - Launches 3 mpcium processes in parallel
   - Each node uses its own configuration and identity

4. **Test Key Generation**
   - Generates 3 random wallet IDs
   - Triggers key generation for all wallets simultaneously
   - Waits for completion (2 minute timeout)

5. **Verify Consistency**
   - Stops all nodes safely
   - Opens each node's database in read-only mode
   - Verifies both ECDSA and EdDSA keys exist for each wallet
   - Ensures all nodes have identical key data

6. **Cleanup**
   - Stops all processes
   - Removes Docker containers
   - Deletes test databases and temporary files

## Configuration

### Test Ports

The tests use different ports to avoid conflicts with running services:

- **NATS**: 4223 (vs 4222 for main)
- **Consul**: 8501 (vs 8500 for main)

### Database Path

Test nodes use a separate database path: `./test_db/` instead of `./db/`

### Test Credentials

- **Badger Password**: `test_password_123`
- **Node Names**: `test_node0`, `test_node1`, `test_node2`

## Troubleshooting

### Common Issues

1. **Binary not found**
   ```
   ❌ mpcium binary not found. Please run 'make' in the root directory first.
   ```
   **Solution**: Run `make` in the root directory to build the binaries.

2. **Port conflicts**
   ```
   Error: port 4223 already in use
   ```
   **Solution**: Run `make clean` to stop any existing test containers.

3. **Permission errors**
   ```
   Error: cannot create test_db directory
   ```
   **Solution**: Ensure you have write permissions in the e2e directory.

### Debugging

To debug test failures:

1. **Check container logs**:
   ```bash
   docker logs nats-server-test
   docker logs consul-test
   ```

2. **Run with verbose output**:
   ```bash
   go test -v -timeout=10m ./...
   ```

3. **Keep test artifacts** (comment out cleanup in the test):
   ```bash
   # Inspect test databases
   ls -la test_db/
   
   # Check test node configurations
   cat test_node0/config.yaml
   ```

## Expected Output

A successful test run should show:

```
🚀 Setting up test infrastructure...
🐳 Starting docker-compose stack...
⏳ Waiting for services to be ready...
🔌 Setting up service clients...
✅ Consul client connected
✅ NATS client connected
🔧 Setting up test nodes...
✅ Test nodes setup complete
📋 Registering peers in Consul...
✅ Registered peer test_node0 with ID xxx
✅ Registered peer test_node1 with ID xxx  
✅ Registered peer test_node2 with ID xxx
🚀 Starting MPC nodes...
✅ Started node test_node0 (PID: xxx)
✅ Started node test_node1 (PID: xxx)
✅ Started node test_node2 (PID: xxx)
🔑 Testing key generation...
📝 Generated wallet IDs: [xxx, xxx, xxx]
🔐 Triggering key generation for wallet xxx
⏳ Waiting for key generation to complete...
✅ Key generation test completed
🔍 Verifying key consistency across nodes...
🛑 Stopping MPC nodes...
🔍 Checking wallet xxx
✅ Found ECDSA key for wallet xxx in node test_node0 (xxx bytes)
✅ Found ECDSA key for wallet xxx in node test_node1 (xxx bytes)
✅ Found ECDSA key for wallet xxx in node test_node2 (xxx bytes)
✅ Found EdDSA key for wallet xxx in node test_node0 (xxx bytes)
✅ Found EdDSA key for wallet xxx in node test_node1 (xxx bytes)
✅ Found EdDSA key for wallet xxx in node test_node2 (xxx bytes)
✅ Key consistency verification completed
🧹 Cleaning up test environment...
✅ Cleanup completed
```

## Integration with CI/CD

To integrate with CI/CD pipelines:

```yaml
# Example GitHub Actions step
- name: Run E2E Tests
  run: |
    make
    cd e2e
    make test
```

The tests are designed to be:
- **Isolated**: No dependencies on external services
- **Deterministic**: Consistent results across runs
- **Self-contained**: All setup and cleanup handled automatically
- **Fast**: Complete in under 10 minutes 