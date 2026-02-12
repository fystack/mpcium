package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fystack/mpcium/pkg/common/pathutil"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/urfave/cli/v3"
)

func registerPeers(ctx context.Context, c *cli.Command) error {
	inputPath := c.String("peers")
	environment := c.String("environment")

	// If no peers path specified, check for peers.json in current directory
	if inputPath == "" {
		inputPath = "peers.json"
	}

	bucketName := "mpc-peers"

	// Validate the input file path for security
	if err := pathutil.ValidateFilePath(inputPath); err != nil {
		return fmt.Errorf("invalid input file path: %w", err)
	}

	// Check if input file exists
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		if inputPath == "peers.json" {
			return fmt.Errorf("peers.json not found in current directory. Please specify the path using --peers flag or create peers.json in the current directory")
		}
		return fmt.Errorf("input file %s does not exist", inputPath)
	}

	// Read peers JSON file
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read JSON file: %w", err)
	}

	// Parse peers data
	peerMap := make(map[string]string)
	if err := json.Unmarshal(data, &peerMap); err != nil {
		return fmt.Errorf("failed to unmarshal JSON data: %w", err)
	}

	if len(peerMap) == 0 {
		return fmt.Errorf("no peers found in the input file")
	}

	// Initialize config and logger
	config.InitViperConfig(c.String("config"))
	appConfig := config.LoadConfig()
	logger.Init(environment, true)

	// Connect to NATS
	nc, err := getNATSConnection(environment, appConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}
	defer nc.Close()

	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("failed to get JetStream context: %w", err)
	}

	peersKV, err := infra.NewNatsKVStore(js, "mpc-peers")
	if err != nil {
		return fmt.Errorf("failed to init mpc-peers KV bucket: %w", err)
	}

	// Register peers in NATS KV
	for nodeName, nodeID := range peerMap {
		key := nodeName

		// Check if the key already exists
		existing, err := peersKV.Get(key)
		if err != nil {
			return fmt.Errorf("failed to check existing key %s: %w", key, err)
		}

		if existing != nil {
			existingID := string(existing)
			if existingID != nodeID {
				return fmt.Errorf("conflict detected: peer %s already exists with ID %s, but trying to register with different ID %s", nodeName, existingID, nodeID)
			}
			fmt.Printf("Peer %s already registered with same ID %s, skipping\n", nodeName, nodeID)
			continue
		}

		// Store the key-value pair
		err = peersKV.Put(key, []byte(nodeID))
		if err != nil {
			return fmt.Errorf("failed to store key %s: %w", key, err)
		}
		fmt.Printf("Registered peer %s with ID %s to NATS KV\n", nodeName, nodeID)
	}

	logger.Info("Successfully registered peers to NATS KV", "peers", peerMap, "bucket", bucketName)
	return nil
}
