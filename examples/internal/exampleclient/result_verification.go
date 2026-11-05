package exampleclient

import (
	"errors"
	"os"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/resultauth"
	"github.com/spf13/viper"
)

const (
	nodePublicKeysFile = "node_public_keys.json"
	// Local setups made before node_public_keys.json existed still have every node's identity file here.
	fallbackIdentityDir = "node0/identity"
)

// WithResultVerification enforces node-signed results when node public keys are available locally.
func WithResultVerification(opts client.Options) client.Options {
	publicKeys, err := loadNodePublicKeys()
	if err != nil {
		logger.Fatal("Failed to load node public keys", err)
	}
	if len(publicKeys) == 0 {
		logger.Warn("No node public keys found; results are not verified. Run: mpcium-cli export-node-keys --identity-dir node0/identity")
		return opts
	}

	opts.ResultVerifyMode = client.ResultVerifyEnforce
	opts.NodePublicKeys = publicKeys
	opts.RequiredNodeSignatures = 1
	// Counting t+1 matching results needs every node's copy, which nodes only keep with per_node_results.
	if viper.GetBool("result_signing.per_node_results") {
		opts.RequiredNodeSignatures = viper.GetInt("mpc_threshold") + 1
	}
	logger.Info("Verifying node-signed results", "nodes", len(publicKeys), "requiredNodeSignatures", opts.RequiredNodeSignatures)
	return opts
}

func loadNodePublicKeys() (map[string]string, error) {
	publicKeys, err := resultauth.LoadPublicKeysFile(nodePublicKeysFile)
	if !errors.Is(err, os.ErrNotExist) {
		return publicKeys, err
	}
	if _, err := os.Stat(fallbackIdentityDir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return resultauth.LoadPublicKeys(fallbackIdentityDir)
}
