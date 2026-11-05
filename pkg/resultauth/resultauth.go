package resultauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fystack/mpcium/pkg/identity"
)

const (
	NodeIDHeader    = "Mpc-Node-Id"
	SignatureHeader = "Mpc-Result-Sig"

	signingDomain = "mpcium-result-v1"
)

var (
	ErrUnsigned         = errors.New("result is not signed by a node")
	ErrUnknownNode      = errors.New("result is signed by an unknown node")
	ErrInvalidSignature = errors.New("result signature is invalid")
)

type Signer interface {
	Sign(data []byte) ([]byte, error)
}

type KeyLookup func(nodeID string) (ed25519.PublicKey, bool)

// SigningPayload binds the signature to the subject so a result cannot be replayed on another topic.
func SigningPayload(subject string, body []byte) []byte {
	payload := make([]byte, 0, len(signingDomain)+len(subject)+len(body)+2)
	payload = append(payload, signingDomain...)
	payload = append(payload, 0)
	payload = append(payload, subject...)
	payload = append(payload, 0)
	return append(payload, body...)
}

func SignHeaders(signer Signer, nodeID, subject string, body []byte) (map[string]string, error) {
	if signer == nil || nodeID == "" {
		return nil, errors.New("result signer and node ID are required")
	}
	signature, err := signer.Sign(SigningPayload(subject, body))
	if err != nil {
		return nil, fmt.Errorf("failed to sign result: %w", err)
	}
	return map[string]string{
		NodeIDHeader:    nodeID,
		SignatureHeader: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// Verify checks the received bytes against the pinned key of the node named in the headers and returns that node ID.
func Verify(lookup KeyLookup, subject string, body []byte, header func(key string) string) (string, error) {
	nodeID := header(NodeIDHeader)
	encodedSignature := header(SignatureHeader)
	if nodeID == "" || encodedSignature == "" {
		return "", ErrUnsigned
	}
	publicKey, ok := lookup(nodeID)
	if !ok {
		return nodeID, fmt.Errorf("%w: %s", ErrUnknownNode, nodeID)
	}
	signature, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return nodeID, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	if !ed25519.Verify(publicKey, SigningPayload(subject, body), signature) {
		return nodeID, ErrInvalidSignature
	}
	return nodeID, nil
}

func NewKeyLookup(publicKeys map[string]string) (KeyLookup, error) {
	keys := make(map[string]ed25519.PublicKey, len(publicKeys))
	for nodeID, encodedKey := range publicKeys {
		publicKey, err := hex.DecodeString(strings.TrimSpace(encodedKey))
		if err != nil {
			return nil, fmt.Errorf("invalid public key for node %s: %w", nodeID, err)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key size for node %s: %d", nodeID, len(publicKey))
		}
		keys[nodeID] = publicKey
	}
	return func(nodeID string) (ed25519.PublicKey, bool) {
		publicKey, ok := keys[nodeID]
		return publicKey, ok
	}, nil
}

// LoadPublicKeys reads node_id -> public_key from <node>_identity.json files, for local setups and tests.
func LoadPublicKeys(identityDir string) (map[string]string, error) {
	paths, err := filepath.Glob(filepath.Join(identityDir, "*_identity.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to list identity files: %w", err)
	}
	publicKeys := make(map[string]string, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", path, err)
		}
		var nodeIdentity identity.NodeIdentity
		if err := json.Unmarshal(data, &nodeIdentity); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		if nodeIdentity.NodeID == "" || nodeIdentity.PublicKey == "" {
			continue
		}
		publicKeys[nodeIdentity.NodeID] = nodeIdentity.PublicKey
	}
	return publicKeys, nil
}

// LoadPublicKeysFile reads a node_id -> hex public key JSON map, as written by setup_identities.sh.
func LoadPublicKeysFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var publicKeys map[string]string
	if err := json.Unmarshal(data, &publicKeys); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return publicKeys, nil
}
