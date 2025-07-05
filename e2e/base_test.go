package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/hashicorp/consul/api"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

const (
	numNodes       = 3
	keygenTimeout  = 10 * time.Minute
	signingTimeout = 5 * time.Minute
)

type TestConfig struct {
	Nats struct {
		URL string `yaml:"url"`
	} `yaml:"nats"`
	Consul struct {
		Address string `yaml:"address"`
	} `yaml:"consul"`
	MPCThreshold         int    `yaml:"mpc_threshold"`
	Environment          string `yaml:"environment"`
	BadgerPassword       string `yaml:"badger_password"`
	EventInitiatorPubkey string `yaml:"event_initiator_pubkey"`
	MPCiumVersion        string `yaml:"mpcium_version"`
	MaxConcurrentKeygen  int    `yaml:"max_concurrent_keygen"`
	DbPath               string `yaml:"db_path"`
}

type E2ETestSuite struct {
	ctx             context.Context
	consulClient    *api.Client
	natsConn        *nats.Conn
	mpcClient       client.MPCClient
	testDir         string
	walletIDs       []string
	mpciumProcesses []*exec.Cmd
	keygenResults   map[string]*event.KeygenResultEvent
	signingResults  map[string]*event.SigningResultEvent
	config          TestConfig
}

func NewE2ETestSuite(testDir string) *E2ETestSuite {
	ctx, _ := context.WithCancel(context.Background())
	return &E2ETestSuite{
		ctx:            ctx,
		testDir:        testDir,
		walletIDs:      make([]string, 0),
		keygenResults:  make(map[string]*event.KeygenResultEvent),
		signingResults: make(map[string]*event.SigningResultEvent),
	}
}

func (s *E2ETestSuite) LoadConfig() error {
	configPath := filepath.Join(s.testDir, "config.test.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &s.config)
}

func (s *E2ETestSuite) RunMakeClean() error {
	cmd := exec.Command("make", "clean")
	cmd.Dir = s.testDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("make clean failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (s *E2ETestSuite) SetupInfrastructure(t *testing.T) {
	t.Log("Setting up test infrastructure...")

	// Start containers using Docker Compose directly
	t.Log("Starting Docker Compose...")

	// Start the compose stack
	t.Log("Starting docker-compose stack...")
	cmd := exec.Command("docker", "compose", "-f", "docker-compose.test.yaml", "up", "-d")
	cmd.Dir = s.testDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Docker compose output: %s", string(output))
		require.NoError(t, err, "Failed to start docker-compose stack")
	}

	t.Log("Docker Compose stack started")

	// Wait for services to be ready
	t.Log("Waiting for services to be ready...")
	time.Sleep(10 * time.Second)

	// Setup clients immediately to establish connections
	s.setupClients(t)

	// Additional wait to ensure stability
	time.Sleep(5 * time.Second)
	t.Log("Infrastructure setup completed and verified")
}

func (s *E2ETestSuite) setupClients(t *testing.T) {
	var err error

	// Use the fixed ports from docker-compose.test.yaml
	consulPort := 8501 // consul-test service maps 8501:8500
	natsPort := 4223   // nats-server-test service maps 4223:4222

	// Setup Consul client
	consulConfig := api.DefaultConfig()
	consulConfig.Address = fmt.Sprintf("localhost:%d", consulPort)
	s.consulClient, err = api.NewClient(consulConfig)
	require.NoError(t, err, "Failed to create Consul client")

	// Test Consul connection
	_, err = s.consulClient.Agent().Self()
	require.NoError(t, err, "Failed to connect to Consul")

	// Setup NATS client
	natsConn, err := nats.Connect(fmt.Sprintf("nats://localhost:%d", natsPort))
	require.NoError(t, err, "Failed to connect to NATS")
	s.natsConn = natsConn

	// Test NATS connection
	err = s.natsConn.Publish("test", []byte("test"))
	require.NoError(t, err, "Failed to publish test message to NATS")

	t.Log("Clients setup completed")
}

func (s *E2ETestSuite) SetupMPCClient(t *testing.T) {
	t.Log("Setting up MPC client...")

	// Setup MPC client
	keyPath := filepath.Join(s.testDir, "test_event_initiator.key")
	t.Logf("Creating MPC client with key path: %s", keyPath)

	// Check if key file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("Key file does not exist: %s. Make sure setupTestNodes ran successfully.", keyPath)
	}

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: s.natsConn,
		KeyPath:  keyPath,
	})
	s.mpcClient = mpcClient
	t.Log("MPC client created")
}

func (s *E2ETestSuite) SetupTestNodes(t *testing.T) {
	t.Log("Setting up test nodes...")

	// Run the setup script (it handles password generation and config updates)
	cmd := exec.Command("bash", "setup_test_identities.sh")
	cmd.Dir = s.testDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Setup script output: %s", string(output))
		require.NoError(t, err, "Failed to run setup script")
	}
	t.Log("Test nodes setup complete")
}

func (s *E2ETestSuite) RegisterPeers(t *testing.T) {
	t.Log("Registering peers in Consul...")

	// Check Consul health before proceeding
	t.Log("Checking Consul health...")
	_, err := s.consulClient.Status().Leader()
	require.NoError(t, err, "Consul is not healthy")
	t.Log("Consul is healthy")

	// Use mpcium register-peers command instead of manual registration
	t.Log("Running mpcium-cli register-peers...")
	nodeDir := filepath.Join(s.testDir, "test_node0")
	cmd := exec.Command("mpcium-cli", "register-peers")
	cmd.Dir = nodeDir
	cmd.Env = append(os.Environ(), "MPCIUM_CONFIG=config.yaml")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("register-peers output: %s", string(output))
		require.NoError(t, err, "Failed to register peers")
	}

	t.Log("Peers registered in Consul")

	// List current peers to verify registration
	t.Log("Listing current peers in Consul...")
	kv := s.consulClient.KV()

	// Get all keys under the mpc_peers/ prefix (matches register-peers command)
	pairs, _, err := kv.List("mpc_peers/", nil)
	if err != nil {
		t.Logf("Failed to list peers: %v", err)
	} else {
		t.Logf("Found %d peer entries in Consul under 'mpc_peers/':", len(pairs))
		for _, pair := range pairs {
			t.Logf("  - Key: %s, Value: %s", pair.Key, string(pair.Value))
		}
	}

	// Verify we have the expected number of peers
	if len(pairs) != numNodes {
		t.Logf("Expected %d peers but found %d", numNodes, len(pairs))
	} else {
		t.Log("All expected peers are registered")
	}

	t.Log("Peer listing completed")
}

func (s *E2ETestSuite) StartNodes(t *testing.T) {
	t.Log("Starting MPC nodes...")

	// Double-check that Consul is still accessible before starting nodes
	t.Log("Verifying Consul is still accessible...")
	_, err := s.consulClient.Status().Leader()
	if err != nil {
		t.Logf("Consul connection test failed: %v", err)
	} else {
		t.Log("Consul is still accessible")
	}

	s.mpciumProcesses = make([]*exec.Cmd, numNodes)

	for i := 0; i < numNodes; i++ {
		nodeName := fmt.Sprintf("test_node%d", i)
		nodeDir := filepath.Join(s.testDir, nodeName)

		// Start node process
		cmd := exec.Command("mpcium", "start", "-n", nodeName)
		cmd.Dir = nodeDir
		cmd.Env = append(os.Environ(), "MPCIUM_CONFIG=config.yaml")

		// Create log files for stdout and stderr
		logDir := filepath.Join(s.testDir, "logs")
		err := os.MkdirAll(logDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create log directory: %v", err)
		}

		stdoutFile, err := os.Create(filepath.Join(logDir, fmt.Sprintf("%s.stdout.log", nodeName)))
		require.NoError(t, err, "Failed to create stdout log file for %s", nodeName)

		stderrFile, err := os.Create(filepath.Join(logDir, fmt.Sprintf("%s.stderr.log", nodeName)))
		require.NoError(t, err, "Failed to create stderr log file for %s", nodeName)

		// Set up logging
		cmd.Stdout = stdoutFile
		cmd.Stderr = stderrFile

		// Start the process
		err = cmd.Start()
		require.NoError(t, err, "Failed to start node %s", nodeName)

		s.mpciumProcesses[i] = cmd
		t.Logf("Started node %s (PID: %d) - logs: %s.stdout.log, %s.stderr.log",
			nodeName, cmd.Process.Pid, nodeName, nodeName)
	}

	// Wait for nodes to be ready
	t.Log("Waiting for nodes to be ready...")
	time.Sleep(5 * time.Second)

	// Verify containers are still accessible
	t.Log("Final verification that Consul is still accessible...")
	_, err = s.consulClient.Status().Leader()
	if err != nil {
		t.Logf("Consul connection test failed after starting nodes: %v", err)
	} else {
		t.Log("Consul is still accessible after starting nodes")
	}

	// Show recent logs from each node
	t.Log("Recent logs from MPC nodes:")
	for i := 0; i < numNodes; i++ {
		nodeName := fmt.Sprintf("test_node%d", i)
		s.ShowRecentLogs(t, nodeName)
	}
}

func (s *E2ETestSuite) ShowRecentLogs(t *testing.T, nodeName string) {
	logDir := filepath.Join(s.testDir, "logs")

	// Show last 10 lines of stdout
	stdoutPath := filepath.Join(logDir, fmt.Sprintf("%s.stdout.log", nodeName))
	if data, err := os.ReadFile(stdoutPath); err == nil && len(data) > 0 {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 10 {
			lines = lines[len(lines)-10:]
		}
		t.Logf("%s stdout (last %d lines):", nodeName, len(lines))
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				t.Logf("   %s", line)
			}
		}
	}

	// Show last 10 lines of stderr
	stderrPath := filepath.Join(logDir, fmt.Sprintf("%s.stderr.log", nodeName))
	if data, err := os.ReadFile(stderrPath); err == nil && len(data) > 0 {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 10 {
			lines = lines[len(lines)-10:]
		}
		t.Logf("%s stderr (last %d lines):", nodeName, len(lines))
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				t.Logf("   %s", line)
			}
		}
	}
}

func (s *E2ETestSuite) WaitForNodesReady(t *testing.T) {
	t.Log("Waiting for all nodes to be ready to accept MPC requests...")

	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatal("Timeout waiting for nodes to be ready")
		case <-ticker.C:
			readyCount := 0

			for i := 0; i < numNodes; i++ {
				nodeName := fmt.Sprintf("test_node%d", i)
				if s.isNodeReady(nodeName) {
					readyCount++
				}
			}

			t.Logf("Nodes ready: %d/%d", readyCount, numNodes)

			if readyCount == numNodes {
				t.Log("All nodes are ready to accept MPC requests!")
				return
			}
		}
	}
}

func (s *E2ETestSuite) isNodeReady(nodeName string) bool {
	logDir := filepath.Join(s.testDir, "logs")
	stderrPath := filepath.Join(logDir, fmt.Sprintf("%s.stderr.log", nodeName))

	data, err := os.ReadFile(stderrPath)
	if err != nil {
		return false
	}

	logContent := string(data)
	// Check for the specific log message that indicates the node is ready
	return strings.Contains(logContent, "ALL PEERS ARE READY! Starting to accept MPC requests")
}

func (s *E2ETestSuite) StopNode(t *testing.T, nodeIndex int) {
	if nodeIndex >= len(s.mpciumProcesses) || s.mpciumProcesses[nodeIndex] == nil {
		t.Logf("Node %d is not running or doesn't exist", nodeIndex)
		return
	}

	cmd := s.mpciumProcesses[nodeIndex]
	nodeName := fmt.Sprintf("test_node%d", nodeIndex)

	t.Logf("Stopping node %s (PID: %d)", nodeName, cmd.Process.Pid)

	// Send SIGTERM for graceful shutdown
	err := cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		t.Logf("Failed to send SIGTERM to node %s: %v", nodeName, err)
	}

	// Wait for graceful shutdown with timeout
	gracefulTimeout := 10 * time.Second
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(gracefulTimeout):
		t.Logf("Node %s didn't stop gracefully, force killing", nodeName)
		err := cmd.Process.Kill()
		if err != nil {
			t.Logf("Failed to kill node %s: %v", nodeName, err)
		}
		<-done // Wait for process to be cleaned up
	case err := <-done:
		if err != nil {
			t.Logf("Node %s stopped with error: %v", nodeName, err)
		} else {
			t.Logf("Node %s stopped gracefully", nodeName)
		}
	}

	s.mpciumProcesses[nodeIndex] = nil
}

func (s *E2ETestSuite) StopNodes(t *testing.T) {
	t.Log("Stopping MPC nodes...")

	if len(s.mpciumProcesses) == 0 {
		t.Log("No nodes to stop")
		return
	}

	// Step 1: Send SIGTERM to all processes for graceful shutdown
	t.Log("Sending SIGTERM to all nodes for graceful shutdown...")
	for i, cmd := range s.mpciumProcesses {
		if cmd != nil && cmd.Process != nil {
			t.Logf("Sending SIGTERM to node %d (PID: %d)", i, cmd.Process.Pid)
			err := cmd.Process.Signal(syscall.SIGTERM)
			if err != nil {
				t.Logf("Failed to send SIGTERM to node %d: %v", i, err)
			}
		}
	}

	// Step 2: Wait for graceful shutdown with timeout
	t.Log("Waiting for graceful shutdown...")
	gracefulTimeout := 10 * time.Second
	deadline := time.Now().Add(gracefulTimeout)

	for time.Now().Before(deadline) {
		allStopped := true

		for i, cmd := range s.mpciumProcesses {
			if cmd != nil && cmd.Process != nil {
				// Check if process is still running
				err := cmd.Process.Signal(syscall.Signal(0))
				if err == nil {
					// Process is still running
					allStopped = false
				} else {
					// Process has stopped, wait for it to clean up
					go func(idx int, process *exec.Cmd) {
						_ = process.Wait() // Clean up zombie process
						t.Logf("Node %d stopped gracefully", idx)
					}(i, cmd)
					s.mpciumProcesses[i] = nil // Mark as stopped
				}
			}
		}

		if allStopped {
			t.Log("All nodes stopped gracefully")
			return
		}

		time.Sleep(500 * time.Millisecond)
	}

	// Step 3: Force kill any remaining processes
	t.Log("Some nodes didn't stop gracefully, force killing remaining processes...")
	for i, cmd := range s.mpciumProcesses {
		if cmd != nil && cmd.Process != nil {
			err := cmd.Process.Signal(syscall.Signal(0))
			if err == nil {
				t.Logf("Force killing node %d (PID: %d)", i, cmd.Process.Pid)
				err := cmd.Process.Kill()
				if err != nil {
					t.Logf("Failed to kill node %d: %v", i, err)
				} else {
					// Wait for the process to be cleaned up
					go func(idx int, process *exec.Cmd) {
						_ = process.Wait()
						t.Logf("Node %d force killed", idx)
					}(i, cmd)
				}
			}
		}
	}

	// Wait for final cleanup
	t.Log("Waiting for final cleanup...")
	time.Sleep(2 * time.Second)

	t.Log("Node shutdown process completed")
}

func (s *E2ETestSuite) CheckKeyInAllNodes(t *testing.T, walletID, keyType, keyName string) {
	key := fmt.Sprintf("%s:%s_v1", keyType, walletID)
	t.Logf("Looking for key: %s", key)

	for i := 0; i < numNodes; i++ {
		nodeName := fmt.Sprintf("test_node%d", i)
		// Skip if node is stopped
		if s.mpciumProcesses[i] == nil {
			t.Logf("Skipping node %s (stopped)", nodeName)
			continue
		}

		// Database is located at: test_node0/test_db/test_node0/
		dbPath := filepath.Join(s.testDir, nodeName, s.config.DbPath, nodeName)
		t.Logf("Database path for %s: %s", nodeName, dbPath)

		// Check if database directory exists
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			t.Logf("Database directory does not exist: %s", dbPath)
			continue
		}

		// Open database in read-only mode with recovery options
		opts := badger.DefaultOptions(dbPath).
			WithCompression(options.ZSTD).
			WithEncryptionKey([]byte(s.config.BadgerPassword)).
			WithIndexCacheSize(100 << 20).
			WithReadOnly(true).
			WithBypassLockGuard(true) // Allow opening even if not properly closed

		db, err := badger.Open(opts)
		if err != nil {
			t.Logf("Could not open database for %s at %s: %v", nodeName, dbPath, err)

			// Try to recover by opening in read-write mode first
			t.Logf("Attempting database recovery for %s", nodeName)
			recoveryOpts := badger.DefaultOptions(dbPath).
				WithCompression(options.ZSTD).
				WithEncryptionKey([]byte(s.config.BadgerPassword)).
				WithIndexCacheSize(100 << 20)

			recoveryDB, recoveryErr := badger.Open(recoveryOpts)
			if recoveryErr != nil {
				t.Logf("Failed to recover database for %s: %v", nodeName, recoveryErr)
				continue
			}

			// Close recovery DB and try read-only again
			if err := recoveryDB.Close(); err != nil {
				t.Logf("Warning: failed to close recovery database for %s: %v", nodeName, err)
			}
			time.Sleep(1 * time.Second)

			db, err = badger.Open(opts)
			if err != nil {
				t.Logf("Still cannot open database for %s after recovery: %v", nodeName, err)
				continue
			}
			t.Logf("Successfully recovered database for %s", nodeName)
		}

		kvStore := &kvstore.BadgerKVStore{DB: db}

		// Check if our specific key exists
		data, err := kvStore.Get(key)
		if err != nil {
			t.Logf("Failed to get key %s from node %s: %v", key, nodeName, err)
		} else if len(data) == 0 {
			t.Logf("Key %s not found in node %s", key, nodeName)
		} else {
			t.Logf("Found key %s in node %s (%d bytes)", key, nodeName, len(data))
		}

		if err := kvStore.Close(); err != nil {
			t.Logf("Warning: failed to close kvStore for %s: %v", nodeName, err)
		}
	}
}

func (s *E2ETestSuite) Cleanup(t *testing.T) {
	t.Log("Cleaning up test environment...")

	// Stop nodes if still running
	s.StopNodes(t)

	// Close MPC client connections
	if s.natsConn != nil {
		s.natsConn.Close()
	}

	// Stop Docker Compose stack
	t.Log("Stopping Docker Compose stack...")
	cmd := exec.Command("docker", "compose", "-f", "docker-compose.test.yaml", "down", "-v")
	cmd.Dir = s.testDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Failed to stop docker-compose stack: %v", err)
		t.Logf("Docker compose down output: %s", string(output))
	} else {
		t.Log("Docker Compose stack stopped")
	}

	// Clean up test data
	testDbPath := filepath.Join(s.testDir, s.config.DbPath)
	os.RemoveAll(testDbPath)

	// Clean up log files
	logPath := filepath.Join(s.testDir, "logs")
	os.RemoveAll(logPath)

	// Clean up test node directories
	for i := 0; i < numNodes; i++ {
		nodeDir := filepath.Join(s.testDir, fmt.Sprintf("test_node%d", i))
		os.RemoveAll(nodeDir)
	}

	// Clean up test initiator files
	os.Remove(filepath.Join(s.testDir, "test_event_initiator.identity.json"))
	os.Remove(filepath.Join(s.testDir, "test_event_initiator.key"))

	t.Log("Cleanup completed")
}
