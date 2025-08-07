package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/common/pathutil"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/constant"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"
)

type ResharingReport struct {
	WalletID        string   `json:"wallet_id"`
	KeyType         string   `json:"key_type"`
	OldParticipants []string `json:"old_participants"`
	NewParticipants []string `json:"new_participants"`
	NewThreshold    int      `json:"new_threshold"`
	Status          string   `json:"status"`
	Error           string   `json:"error,omitempty"`
}

type KeyReport struct {
	Key                string   `json:"key"`
	WalletID           string   `json:"wallet_id"`
	KeyType            string   `json:"key_type"`
	ParticipantCount   int      `json:"participant_count"`
	ParticipantPeerIDs []string `json:"participant_peer_ids"`
	Threshold          int      `json:"threshold"`
	Version            int      `json:"version"`
}

type KeyToReshare struct {
	WalletID   string
	KeyType    types.KeyType
	KeyTypeStr string // Store the original key type string from JSON
}

type LowParticipantReport struct {
	TotalKeysFound int         `json:"total_keys_found"`
	Keys           []KeyReport `json:"keys"`
}

func main() {
	app := &cli.Command{
		Name:  "execute-reshare",
		Usage: "Execute resharing operations for keys with low participants",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "key-path",
				Aliases: []string{"k"},
				Value:   "./event_initiator.key",
				Usage:   "Path to the key file",
			},
			&cli.BoolFlag{
				Name:    "encrypted",
				Aliases: []string{"e"},
				Value:   false,
				Usage:   "Whether the key is encrypted",
			},
			&cli.StringFlag{
				Name:    "password",
				Aliases: []string{"p"},
				Value:   "",
				Usage:   "Password for encrypted key (will prompt if not provided and key is encrypted)",
			},
			&cli.StringFlag{
				Name:    "report-file",
				Aliases: []string{"r"},
				Value:   "low_participant_keys.json",
				Usage:   "Path to the report file containing keys to reshare",
			},
		},
		Action: executeReshare,
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		logger.Fatal("Application failed", err)
	}
}

func executeReshare(ctx context.Context, cmd *cli.Command) error {
	config.InitViperConfig()
	environment := viper.GetString("environment")
	logger.Init(environment, true)

	// Get CLI arguments
	keyPath := cmd.String("key-path")
	encrypted := cmd.Bool("encrypted")
	password := cmd.String("password")
	reportFile := cmd.String("report-file")

	// If encrypted but no password provided, prompt for it
	if encrypted && password == "" {
		fmt.Print("Enter password for encrypted key: ")
		fmt.Scanln(&password)
	}

	// Validate key file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return fmt.Errorf("key file not found: %s", keyPath)
	}

	// Load keys to reshare from the report file
	keysToReshare, err := loadKeysFromReport(reportFile)
	if err != nil {
		return fmt.Errorf("failed to load keys from report: %w", err)
	}

	if len(keysToReshare) == 0 {
		logger.Info("No keys need resharing")
		return nil
	}

	logger.Info("Keys found for resharing", "count", len(keysToReshare))

	// Get available nodes from mpc_peers
	consulClient := infra.GetConsulClient(environment)
	kv := consulClient.KV()

	availableNodes, err := getAvailableNodes(kv)
	if err != nil {
		return fmt.Errorf("failed to get available nodes: %w", err)
	}

	logger.Info("Available nodes found", "count", len(availableNodes), "nodes", availableNodes)

	if len(availableNodes) < 2 {
		return fmt.Errorf("not enough nodes available for resharing: only %d nodes available, need at least 2", len(availableNodes))
	}

	// Connect to NATS
	natsConn, err := GetNATSConnection(environment)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}
	defer natsConn.Close()
	defer natsConn.Drain()

	// Init MPC client
	mpcClient := client.NewMPCClient(client.Options{
		NatsConn:  natsConn,
		KeyPath:   keyPath,
		Encrypted: encrypted,
		Password:  password,
	})

	// Init keyinfo store
	keyStore := keyinfo.NewStore(kv)

	var reports []ResharingReport
	completedReshares := make(map[string]bool) // Use composite key: walletID:keyType
	completionNotify := make(chan struct{}, 1) // Channel to notify when all operations complete

	// Setup resharing result handler
	err = mpcClient.OnResharingResult(func(evt event.ResharingResultEvent) {
		logger.Info("Received resharing result", "wallet_id", evt.WalletID, "result_type", evt.ResultType, "key_type", evt.KeyType)

		// Create composite key for tracking completion
		compositeKey := fmt.Sprintf("%s:%s", evt.WalletID, evt.KeyType)
		completedReshares[compositeKey] = true

		if evt.ResultType == event.ResultTypeError {
			logger.Error("Resharing failed",
				fmt.Errorf("resharing failed for wallet %s (%s): %s", evt.WalletID, evt.KeyType, evt.ErrorReason),
				"walletID", evt.WalletID,
				"keyType", evt.KeyType,
				"error_reason", evt.ErrorReason,
			)
			// Update report
			found := false
			for i := range reports {
				if reports[i].WalletID == evt.WalletID && reports[i].KeyType == string(evt.KeyType) {
					reports[i].Status = "failed"
					reports[i].Error = evt.ErrorReason
					found = true
					break
				}
			}
			if !found {
				logger.Warn("Could not find report to update for failed resharing", "wallet_id", evt.WalletID, "key_type", evt.KeyType)
			}
		} else {
			logger.Info("Resharing succeeded",
				"walletID", evt.WalletID,
				"keyType", evt.KeyType,
				"newThreshold", evt.NewThreshold,
			)

			// Update report
			found := false
			for i := range reports {
				if reports[i].WalletID == evt.WalletID && reports[i].KeyType == string(evt.KeyType) {
					reports[i].Status = "completed"
					found = true
					break
				}
			}
			if !found {
				logger.Warn("Could not find report to update for successful resharing", "wallet_id", evt.WalletID, "key_type", evt.KeyType)
			}
		}

		logger.Info("Resharing result processed", "wallet_id", evt.WalletID, "key_type", evt.KeyType, "total_completed", len(completedReshares))

		// Check if all operations completed and notify
		if len(completedReshares) >= len(keysToReshare) {
			select {
			case completionNotify <- struct{}{}:
				logger.Info("All resharing operations completed, notifying waiting loop")
			default:
				// Channel already has a value, no need to send again
			}
		}
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to OnResharingResult: %w", err)
	}

	// Calculate new threshold (majority)
	newThreshold := 1

	logger.Info("Starting resharing for all keys", "total_keys", len(keysToReshare), "new_threshold", newThreshold)

	// Execute resharing for each key
	processedCount := 0
	for _, keyToReshare := range keysToReshare {
		processedCount++
		logger.Info("Processing key", "current", processedCount, "total", len(keysToReshare), "wallet_id", keyToReshare.WalletID, "key_type", keyToReshare.KeyType)

		// Get current keyinfo using the key type string from JSON
		key := fmt.Sprintf("%s:%s", keyToReshare.KeyTypeStr, keyToReshare.WalletID)

		logger.Info("Looking up keyinfo", "key", key, "wallet_id", keyToReshare.WalletID)
		currentInfo, err := keyStore.Get(key)
		if err != nil {
			logger.Warn("Failed to get current keyinfo", "walletID", keyToReshare.WalletID, "key", key, "error", err)
			// Still create a report for failed keyinfo lookup
			report := ResharingReport{
				WalletID: keyToReshare.WalletID,
				KeyType:  string(keyToReshare.KeyType),
				Status:   "failed",
				Error:    fmt.Sprintf("Failed to get keyinfo: %v", err),
			}
			reports = append(reports, report)
			continue
		}

		logger.Info("Found keyinfo", "wallet_id", keyToReshare.WalletID, "participants", len(currentInfo.ParticipantPeerIDs), "threshold", currentInfo.Threshold)

		report := ResharingReport{
			WalletID:        keyToReshare.WalletID,
			KeyType:         string(keyToReshare.KeyType),
			OldParticipants: currentInfo.ParticipantPeerIDs,
			NewParticipants: availableNodes,
			NewThreshold:    newThreshold,
			Status:          "initiated",
		}
		reports = append(reports, report)

		// Create resharing message
		resharingMsg := &types.ResharingMessage{
			SessionID:    uuid.NewString(),
			WalletID:     keyToReshare.WalletID,
			NodeIDs:      availableNodes,
			NewThreshold: newThreshold,
			KeyType:      keyToReshare.KeyType,
		}

		logger.Info("Initiating resharing", "wallet_id", keyToReshare.WalletID, "session_id", resharingMsg.SessionID)
		err = mpcClient.Resharing(resharingMsg)
		if err != nil {
			logger.Error("Failed to initiate resharing", err,
				"walletID", keyToReshare.WalletID,
			)
			// Update the report we just added
			reports[len(reports)-1].Status = "failed"
			reports[len(reports)-1].Error = err.Error()
		} else {
			logger.Info("Resharing initiated successfully",
				"walletID", keyToReshare.WalletID,
				"keyType", keyToReshare.KeyType,
				"newParticipants", len(availableNodes),
				"newThreshold", newThreshold,
			)
		}

		// Small delay between reshares
		logger.Info("Waiting 1 second before next key", "remaining", len(keysToReshare)-processedCount)
		time.Sleep(1 * time.Second)
	}

	logger.Info("Finished processing all keys", "total_processed", processedCount, "total_reports", len(reports))

	// Wait for completion or timeout
	timeout := time.NewTimer(10 * time.Minute)
	ticker := time.NewTicker(30 * time.Second)
	defer timeout.Stop()
	defer ticker.Stop()

	logger.Info("Waiting for resharing operations to complete...", "total_expected", len(keysToReshare))

	// Immediate check in case all operations completed before we started waiting
	if len(completedReshares) >= len(keysToReshare) {
		logger.Info("All resharing operations already completed")
		goto saveReport
	}

	for {
		select {
		case <-timeout.C:
			logger.Warn("Timeout reached, some resharing operations may not have completed",
				"completed", len(completedReshares),
				"expected", len(keysToReshare),
				"completed_wallets", getCompletedKeys(completedReshares),
			)
			goto saveReport
		case <-ticker.C:
			completed := len(completedReshares)
			total := len(keysToReshare)
			logger.Info("Resharing progress",
				"completed", completed,
				"total", total,
				"completed_wallets", getCompletedKeys(completedReshares),
			)

			if completed >= total {
				logger.Info("All resharing operations completed")
				goto saveReport
			}
		case <-completionNotify:
			logger.Info("Received notification that all resharing operations are complete. Exiting waiting loop.")
			goto saveReport
		}
	}

saveReport:
	// Save report
	reportFileName := "resharing_report.json"
	reportJSON, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal report", err)
	} else {
		if err := os.WriteFile(reportFileName, reportJSON, 0644); err != nil {
			logger.Error("Failed to write report", err)
		} else {
			logger.Info("Resharing report saved", "file", reportFileName)
		}
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Press Ctrl+C to exit")
	<-stop
	fmt.Println("Shutting down.")

	return nil
}

func loadKeysFromReport(filename string) ([]KeyToReshare, error) {
	// Validate the file path for security
	if err := pathutil.ValidateFilePath(filename); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file: %w", err)
	}

	var report LowParticipantReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	var keysToReshare []KeyToReshare

	for _, keyReport := range report.Keys {
		walletID := keyReport.WalletID
		keyTypeStr := strings.ToLower(keyReport.KeyType)

		// Map key type string to types.KeyType
		var keyType types.KeyType
		switch keyTypeStr {
		case "ecdsa":
			keyType = types.KeyTypeSecp256k1
		case "eddsa":
			keyType = types.KeyTypeEd25519
		default:
			// Default to EdDSA if unknown
			keyType = types.KeyTypeEd25519
			logger.Warn("Unknown key type, defaulting to EdDSA",
				"key", keyReport.Key,
				"key_type", keyReport.KeyType,
				"wallet_id", walletID,
			)
		}

		keysToReshare = append(keysToReshare, KeyToReshare{
			WalletID:   walletID,
			KeyType:    keyType,
			KeyTypeStr: keyTypeStr,
		})
	}

	return keysToReshare, nil
}

func getAvailableNodes(kv infra.ConsulKV) ([]string, error) {
	pairs, _, err := kv.List("mpc_peers/", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list mpc_peers: %w", err)
	}

	var nodeIDs []string
	for _, pair := range pairs {
		// Extract node ID from the value
		nodeID := string(pair.Value)
		if nodeID != "" {
			nodeIDs = append(nodeIDs, nodeID)
		}
	}

	return nodeIDs, nil
}

func GetNATSConnection(environment string) (*nats.Conn, error) {
	url := viper.GetString("nats.url")
	opts := []nats.Option{
		nats.MaxReconnects(-1), // retry forever
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectHandler(func(nc *nats.Conn) {
			logger.Warn("Disconnected from NATS")
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("Reconnected to NATS", "url", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			logger.Info("NATS connection closed!")
		}),
	}

	if environment == constant.EnvProduction {
		clientCert := filepath.Join(".", "certs", "client-cert.pem")
		clientKey := filepath.Join(".", "certs", "client-key.pem")
		caCert := filepath.Join(".", "certs", "rootCA.pem")

		opts = append(opts,
			nats.ClientCert(clientCert, clientKey),
			nats.RootCAs(caCert),
			nats.UserInfo(viper.GetString("nats.username"), viper.GetString("nats.password")),
		)
	}

	return nats.Connect(url, opts...)
}

func getCompletedKeys(completedReshares map[string]bool) []string {
	keys := make([]string, 0, len(completedReshares))
	for key := range completedReshares {
		keys = append(keys, key)
	}
	return keys
}
