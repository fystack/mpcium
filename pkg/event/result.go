package event

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// NodeResult is a result event that a node signs with its identity key so the
// consumer can verify it was produced by the MPC network and not injected or
// tampered with by a compromised message broker.
type nodeResult interface {
	// Raw returns the canonical bytes that the node signed (signature cleared).
	Raw() ([]byte, error)
	setNodeSignature(nodeID string, signature []byte)
}

// ResultSigner is the node's identity key holder (identity.Store satisfies it).
type ResultSigner interface {
	NodeID() string
	Sign(data []byte) ([]byte, error)
}

// NodeKeyLookup returns the ed25519 public key of an MPC node.
type NodeKeyLookup func(nodeID string) ([]byte, error)

// SignNodeResult fills NodeID and ResultSignature on a result event.
func SignNodeResult(res nodeResult, signer ResultSigner) error {
	if signer == nil {
		return fmt.Errorf("result signer is required")
	}
	raw, err := res.Raw()
	if err != nil {
		return fmt.Errorf("failed to marshal result for signing: %w", err)
	}
	sig, err := signer.Sign(raw)
	if err != nil {
		return fmt.Errorf("failed to sign result: %w", err)
	}
	res.setNodeSignature(signer.NodeID(), sig)
	return nil
}

// VerifyNodeResult checks a result event's signature against the emitting
// node's ed25519 public key. It returns an error when the event is unsigned,
// comes from an unknown node, or the signature does not match.
func VerifyNodeResult(nodeID string, signature []byte, res interface{ Raw() ([]byte, error) }, lookup NodeKeyLookup) error {
	if lookup == nil {
		return nil
	}
	if nodeID == "" || len(signature) == 0 {
		return fmt.Errorf("result event is not signed by the node")
	}
	publicKey, err := lookup(nodeID)
	if err != nil {
		return fmt.Errorf("failed to get public key of node %s: %w", nodeID, err)
	}
	raw, err := res.Raw()
	if err != nil {
		return fmt.Errorf("failed to marshal result for verification: %w", err)
	}
	if !ed25519.Verify(publicKey, raw, signature) {
		return fmt.Errorf("invalid result signature from node %s", nodeID)
	}
	return nil
}

func (e *SigningResultEvent) Raw() ([]byte, error) {
	raw := *e
	raw.NodeID, raw.ResultSignature = "", nil
	return json.Marshal(raw)
}

func (e *SigningResultEvent) setNodeSignature(nodeID string, signature []byte) {
	e.NodeID, e.ResultSignature = nodeID, signature
}

func (e *KeygenResultEvent) Raw() ([]byte, error) {
	raw := *e
	raw.NodeID, raw.ResultSignature = "", nil
	return json.Marshal(raw)
}

func (e *KeygenResultEvent) setNodeSignature(nodeID string, signature []byte) {
	e.NodeID, e.ResultSignature = nodeID, signature
}

func (e *ResharingResultEvent) Raw() ([]byte, error) {
	raw := *e
	raw.NodeID, raw.ResultSignature = "", nil
	return json.Marshal(raw)
}

func (e *ResharingResultEvent) setNodeSignature(nodeID string, signature []byte) {
	e.NodeID, e.ResultSignature = nodeID, signature
}

// NodeScopedIdempotentKey keeps JetStream from deduplicating the same result published by different nodes.
func NodeScopedIdempotentKey(key, nodeID string) string {
	return key + ":" + nodeID
}
