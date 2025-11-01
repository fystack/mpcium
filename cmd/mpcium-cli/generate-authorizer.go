package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"time"

	"filippo.io/age"
	"github.com/fystack/mpcium/pkg/common/pathutil"
	"github.com/fystack/mpcium/pkg/encryption"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/urfave/cli/v3"
)

// AuthorizerIdentity struct to store authorizer metadata
type AuthorizerIdentity struct {
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm,omitempty"`
	PublicKey   string `json:"public_key"`
	CreatedAt   string `json:"created_at"`
	CreatedBy   string `json:"created_by"`
	MachineOS   string `json:"machine_os"`
	MachineName string `json:"machine_name"`
}

// validateAuthorizerName checks if the authorizer name is valid (no spaces, special characters)
func validateAuthorizerName(name string) error {
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	// Only allow alphanumeric characters, hyphens, and underscores
	validNamePattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validNamePattern.MatchString(name) {
		return fmt.Errorf("name can only contain alphanumeric characters, hyphens, and underscores (no spaces or special characters)")
	}

	return nil
}

func generateAuthorizerIdentity(ctx context.Context, c *cli.Command) error {
	name := c.String("name")
	outputDir := c.String("output-dir")
	encrypt := c.Bool("encrypt")
	overwrite := c.Bool("overwrite")
	algorithm := c.String("algorithm")

	// Validate authorizer name
	if err := validateAuthorizerName(name); err != nil {
		return err
	}

	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}

	if !slices.Contains(
		[]string{string(types.EventInitiatorKeyTypeEd25519), string(types.EventInitiatorKeyTypeP256)},
		algorithm,
	) {
		return fmt.Errorf("invalid algorithm: %s. Must be %s or %s",
			algorithm,
			types.EventInitiatorKeyTypeEd25519,
			types.EventInitiatorKeyTypeP256,
		)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if files already exist before proceeding
	identityPath := filepath.Join(outputDir, fmt.Sprintf("%s.authorizer.identity.json", name))
	keyPath := filepath.Join(outputDir, fmt.Sprintf("%s.authorizer.key", name))
	encKeyPath := keyPath + ".age"

	// Check for existing identity file
	if _, err := os.Stat(identityPath); err == nil && !overwrite {
		return fmt.Errorf(
			"identity file already exists: %s (use --overwrite to force)",
			identityPath,
		)
	}

	// Check for existing key files
	if _, err := os.Stat(keyPath); err == nil && !overwrite {
		return fmt.Errorf("key file already exists: %s (use --overwrite to force)", keyPath)
	}

	if encrypt {
		if _, err := os.Stat(encKeyPath); err == nil && !overwrite {
			return fmt.Errorf(
				"encrypted key file already exists: %s (use --overwrite to force)",
				encKeyPath,
			)
		}
	}

	// Generate keys based on algorithm
	var keyData encryption.KeyData
	var err error

	if algorithm == string(types.EventInitiatorKeyTypeEd25519) {
		keyData, err = encryption.GenerateEd25519Keys()
	} else if algorithm == string(types.EventInitiatorKeyTypeP256) {
		keyData, err = encryption.GenerateP256Keys()
	}

	if err != nil {
		return fmt.Errorf("failed to generate %s keys: %w", algorithm, err)
	}

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create Identity object
	identity := AuthorizerIdentity{
		Name:        name,
		Algorithm:   algorithm,
		PublicKey:   keyData.PublicKeyHex,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		CreatedBy:   currentUser.Username,
		MachineOS:   runtime.GOOS,
		MachineName: hostname,
	}

	// Save identity JSON
	identityBytes, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity JSON: %w", err)
	}

	if err := os.WriteFile(identityPath, identityBytes, 0600); err != nil {
		return fmt.Errorf("failed to save identity file: %w", err)
	}

	// Handle private key (with optional encryption)
	if encrypt {
		// Use requestPassword function instead of inline password handling
		passphrase, err := requestPassword()
		if err != nil {
			return err
		}

		// Create encrypted key file
		encKeyPath := keyPath + ".age"

		// Validate the encrypted key path for security
		if err := pathutil.ValidateFilePath(encKeyPath); err != nil {
			return fmt.Errorf("invalid encrypted key file path: %w", err)
		}

		outFile, err := os.Create(encKeyPath)
		if err != nil {
			return fmt.Errorf("failed to create encrypted private key file: %w", err)
		}
		defer outFile.Close()

		// Set up age encryption
		recipient, err := age.NewScryptRecipient(passphrase)
		if err != nil {
			return fmt.Errorf("failed to create scrypt recipient: %w", err)
		}

		identityWriter, err := age.Encrypt(outFile, recipient)
		if err != nil {
			return fmt.Errorf("failed to create age encryption writer: %w", err)
		}

		// Write the encrypted private key
		if _, err := identityWriter.Write([]byte(keyData.PrivateKeyHex)); err != nil {
			return fmt.Errorf("failed to write encrypted private key: %w", err)
		}

		if err := identityWriter.Close(); err != nil {
			return fmt.Errorf("failed to finalize age encryption: %w", err)
		}

		fmt.Println("✅ Successfully generated authorizer identity:")
		fmt.Println("- Encrypted Private Key:", encKeyPath)
		fmt.Println("- Identity JSON:", identityPath)
		return nil
	} else {
		fmt.Println("WARNING: You are generating the private key without encryption.")
		fmt.Println("This is less secure. Consider using --encrypt flag for better security.")

		if err := os.WriteFile(keyPath, []byte(keyData.PrivateKeyHex), 0600); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
	}

	fmt.Println("✅ Successfully generated authorizer identity:")
	fmt.Println("- Private Key:", keyPath)
	fmt.Println("- Identity JSON:", identityPath)
	return nil
}
