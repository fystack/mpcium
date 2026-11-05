package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/fystack/mpcium/pkg/resultauth"
	"github.com/urfave/cli/v3"
)

func exportNodeKeys(ctx context.Context, c *cli.Command) error {
	publicKeys := make(map[string]string)
	for _, identityDir := range c.StringSlice("identity-dir") {
		dirKeys, err := resultauth.LoadPublicKeys(identityDir)
		if err != nil {
			return err
		}
		for nodeID, publicKey := range dirKeys {
			if existing, ok := publicKeys[nodeID]; ok && existing != publicKey {
				return fmt.Errorf("node %s has different public keys in the identity directories", nodeID)
			}
			publicKeys[nodeID] = publicKey
		}
	}
	if len(publicKeys) == 0 {
		return fmt.Errorf("no *_identity.json files found in %v", c.StringSlice("identity-dir"))
	}
	if _, err := resultauth.NewKeyLookup(publicKeys); err != nil {
		return err
	}
	if err := checkAllPeersHaveKeys(c.String("peers"), publicKeys); err != nil {
		return err
	}

	data, err := json.MarshalIndent(publicKeys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode node public keys: %w", err)
	}
	data = append(data, '\n')

	outputPath := c.String("output")
	if outputPath == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if _, err := os.Stat(outputPath); err == nil && !c.Bool("overwrite") {
		return fmt.Errorf("file %s already exists, use --overwrite to replace it", outputPath)
	}
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", outputPath, err)
	}
	fmt.Printf("Wrote %d node public keys to %s\n", len(publicKeys), outputPath)
	return nil
}

func checkAllPeersHaveKeys(peersPath string, publicKeys map[string]string) error {
	data, err := os.ReadFile(peersPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", peersPath, err)
	}
	var peers map[string]string
	if err := json.Unmarshal(data, &peers); err != nil {
		return fmt.Errorf("failed to parse %s: %w", peersPath, err)
	}

	var missing []string
	for name, nodeID := range peers {
		if _, ok := publicKeys[nodeID]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("no identity file found for peers %v", missing)
	}
	return nil
}
