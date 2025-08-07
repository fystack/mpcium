package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/spf13/viper"
)

type KeyReport struct {
	Key                string   `json:"key"`
	WalletID           string   `json:"wallet_id"`
	KeyType            string   `json:"key_type"`
	ParticipantCount   int      `json:"participant_count"`
	ParticipantPeerIDs []string `json:"participant_peer_ids"`
	Threshold          int      `json:"threshold"`
	Version            int      `json:"version"`
}

// extractWalletIDAndKeyType extracts wallet ID and key type from the consul key
// Format: threshold_keyinfo/eddsa:0f2d9b28-7066-4571-855c-980983928fe8:0
// or: threshold_keyinfo/ecdsa:wallet-id:index
func extractWalletIDAndKeyType(consulKey string) (walletID, keyType string) {
	// Remove the prefix
	withoutPrefix := strings.TrimPrefix(consulKey, "threshold_keyinfo/")

	// Split by colon to get key type and wallet info
	parts := strings.SplitN(withoutPrefix, ":", 2)
	if len(parts) >= 2 {
		keyType = parts[0]
		walletID = parts[1] // This includes the wallet ID and any suffix like ":0"
	} else {
		// Fallback: if no colon, treat the whole thing as wallet ID
		walletID = withoutPrefix
		keyType = "unknown"
	}

	return walletID, keyType
}

func main() {
	config.InitViperConfig()
	environment := viper.GetString("environment")
	logger.Init(environment, true)

	consulClient := infra.GetConsulClient(environment)
	// Get KV client
	kv := consulClient.KV()

	// List all keys under threshold_keyinfo/
	pairs, _, err := kv.List("threshold_keyinfo/", nil)
	if err != nil {
		logger.Fatal("Failed to list keys", err)
	}

	var keysWithLowParticipants []KeyReport

	// Check each key
	for _, pair := range pairs {
		var info keyinfo.KeyInfo
		if err := json.Unmarshal(pair.Value, &info); err != nil {
			logger.Warn("Failed to unmarshal key",
				"key", pair.Key,
				"error", err,
			)
			continue
		}

		// Check if participants are less than 3
		if len(info.ParticipantPeerIDs) < 3 {
			walletID, keyType := extractWalletIDAndKeyType(pair.Key)

			report := KeyReport{
				Key:                pair.Key,
				WalletID:           walletID,
				KeyType:            keyType,
				ParticipantCount:   len(info.ParticipantPeerIDs),
				ParticipantPeerIDs: info.ParticipantPeerIDs,
				Threshold:          info.Threshold,
				Version:            info.Version,
			}
			keysWithLowParticipants = append(keysWithLowParticipants, report)
			logger.Info("Found key with low participants",
				"key", pair.Key,
				"wallet_id", walletID,
				"key_type", keyType,
				"count", len(info.ParticipantPeerIDs),
				"participants", info.ParticipantPeerIDs,
			)
		}
	}

	// Create report
	report := struct {
		TotalKeysFound int         `json:"total_keys_found"`
		Keys           []KeyReport `json:"keys"`
	}{
		TotalKeysFound: len(keysWithLowParticipants),
		Keys:           keysWithLowParticipants,
	}

	// Save to JSON file
	outputFile := "low_participant_keys.json"
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logger.Fatal("Failed to marshal report", err)
	}

	if err := os.WriteFile(outputFile, reportJSON, 0644); err != nil {
		logger.Fatal("Failed to write report", err)
	}

	logger.Info("Report generated",
		"total_keys", len(keysWithLowParticipants),
		"output_file", outputFile,
	)
}
