package frost

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/fystack/mpcium/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	mpsProtocol "github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

// FROSTProtocol implements the Protocol interface using FROST for EdDSA
type FROSTProtocol struct {
	pool *pool.Pool
}

// NewFROSTProtocol creates a new FROST protocol adapter
func NewFROSTProtocol() *FROSTProtocol {
	return &FROSTProtocol{
		pool: pool.NewPool(0), // Use max threads
	}
}

// Close cleans up resources
func (p *FROSTProtocol) Close() {
	if p.pool != nil {
		p.pool.TearDown()
	}
}

// Name returns the protocol name
func (p *FROSTProtocol) Name() string {
	return "FROST"
}

// KeyGen starts a distributed key generation for EdDSA
func (p *FROSTProtocol) KeyGen(selfID string, partyIDs []string, threshold int) (protocol.Party, error) {
	// Convert string IDs to party.ID
	ids := make([]party.ID, len(partyIDs))
	for i, id := range partyIDs {
		ids[i] = party.ID(id)
	}

	// Create the FROST keygen protocol for Ed25519/Taproot
	startFunc := frost.KeygenTaproot(party.ID(selfID), ids, threshold)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST keygen handler: %w", err)
	}

	return &frostPartyAdapter{
		handler:   handler,
		selfID:    selfID,
		isTaproot: true,
	}, nil
}

// Refresh refreshes shares from an existing config
func (p *FROSTProtocol) Refresh(cfg protocol.KeyGenConfig) (protocol.Party, error) {
	// Convert to FROST config
	frostConfig, err := toFROSTConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Get party IDs from config
	partyIDs := cfg.GetPartyIDs()
	ids := make([]party.ID, len(partyIDs))
	for i, id := range partyIDs {
		ids[i] = party.ID(id)
	}

	// Create refresh protocol
	startFunc := frost.Refresh(frostConfig, ids)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST refresh handler: %w", err)
	}

	return &frostPartyAdapter{
		handler:   handler,
		selfID:    cfg.GetPartyID(),
		isTaproot: false,
	}, nil
}

// Sign starts a signing protocol
func (p *FROSTProtocol) Sign(cfg protocol.KeyGenConfig, signers []string, messageHash []byte) (protocol.Party, error) {
	// Convert to FROST config
	frostConfig, err := toFROSTConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Convert signer IDs
	signerIDs := make([]party.ID, len(signers))
	for i, id := range signers {
		signerIDs[i] = party.ID(id)
	}

	// Create sign protocol
	startFunc := frost.Sign(frostConfig, signerIDs, messageHash)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST sign handler: %w", err)
	}

	return &frostPartyAdapter{
		handler:   handler,
		selfID:    cfg.GetPartyID(),
		isTaproot: false,
	}, nil
}

// PreSign starts a presigning protocol
func (p *FROSTProtocol) PreSign(cfg protocol.KeyGenConfig, signers []string) (protocol.Party, error) {
	// FROST doesn't support presigning in the same way as ECDSA protocols
	return nil, errors.New("FROST protocol does not support presigning")
}

// PreSignOnline completes a signature with a presignature
func (p *FROSTProtocol) PreSignOnline(cfg protocol.KeyGenConfig, preSig protocol.PreSignature, messageHash []byte) (protocol.Party, error) {
	// FROST doesn't support presigning in the same way as ECDSA protocols
	return nil, errors.New("FROST protocol does not support presigning")
}

// frostPartyAdapter adapts mpsProtocol.Handler to protocol.Party
type frostPartyAdapter struct {
	handler   *mpsProtocol.MultiHandler
	selfID    string
	isTaproot bool
	mu        sync.Mutex
	done      bool
	result    interface{}
	err       error
}

func (p *frostPartyAdapter) Update(msg protocol.Message) error {
	// Convert to MPS message format
	// If broadcast, To is nil. Otherwise, it's the first recipient
	var to party.ID
	if !msg.IsBroadcast() && len(msg.GetTo()) > 0 {
		to = party.ID(msg.GetTo()[0])
	}

	mpsMsg := &mpsProtocol.Message{
		From:      party.ID(msg.GetFrom()),
		To:        to,
		Broadcast: msg.IsBroadcast(),
		Data:      msg.GetData(),
	}

	// Check if handler can accept the message
	if !p.handler.CanAccept(mpsMsg) {
		return errors.New("message rejected by handler")
	}

	// Update handler with message
	// Note: MultiHandler doesn't have Update method, we need to send via Accept
	p.handler.Accept(mpsMsg)
	return nil
}

func (p *frostPartyAdapter) Messages() <-chan protocol.Message {
	ch := make(chan protocol.Message)

	go func() {
		defer close(ch)

		for {
			select {
			case msg, ok := <-p.handler.Listen():
				if !ok {
					// Protocol finished
					p.mu.Lock()
					p.done = true
					p.result, p.err = p.handler.Result()
					p.mu.Unlock()
					return
				}

				// Convert and send message
				var toList []string
				if !msg.Broadcast && msg.To != "" {
					toList = []string{string(msg.To)}
				}

				ch <- &messageAdapter{
					from:      string(msg.From),
					to:        toList,
					data:      msg.Data,
					broadcast: msg.Broadcast,
				}
			}
		}
	}()

	return ch
}

func (p *frostPartyAdapter) Errors() <-chan error {
	// FROST doesn't have a separate error channel
	// Errors are returned in Result()
	ch := make(chan error)
	close(ch)
	return ch
}

func (p *frostPartyAdapter) Done() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done
}

func (p *frostPartyAdapter) Result() (interface{}, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.done {
		return nil, errors.New("protocol not finished")
	}

	if p.err != nil {
		return nil, p.err
	}

	// Convert result to appropriate type
	switch r := p.result.(type) {
	case *frost.Signature:
		return &frostSignatureAdapter{sig: r}, nil
	case *frost.Config:
		return &frostConfigAdapter{
			config:    r,
			isTaproot: false,
		}, nil
	case *frost.TaprootConfig:
		return &frostConfigAdapter{
			taprootConfig: r,
			isTaproot:     true,
		}, nil
	default:
		return nil, fmt.Errorf("unexpected result type: %T", r)
	}
}

// messageAdapter implements protocol.Message
type messageAdapter struct {
	from      string
	to        []string
	data      []byte
	broadcast bool
}

func (m *messageAdapter) GetFrom() string   { return m.from }
func (m *messageAdapter) GetTo() []string   { return m.to }
func (m *messageAdapter) GetData() []byte   { return m.data }
func (m *messageAdapter) IsBroadcast() bool { return m.broadcast }

// frostConfigAdapter implements protocol.KeyGenConfig for FROST
type frostConfigAdapter struct {
	config        *frost.Config
	taprootConfig *frost.TaprootConfig
	isTaproot     bool
}

func (c *frostConfigAdapter) GetPartyID() string {
	if c.isTaproot && c.taprootConfig != nil {
		return string(c.taprootConfig.ID)
	}
	if c.config != nil {
		return string(c.config.ID)
	}
	return ""
}

func (c *frostConfigAdapter) GetThreshold() int {
	if c.isTaproot && c.taprootConfig != nil {
		return c.taprootConfig.Threshold
	}
	if c.config != nil {
		return c.config.Threshold
	}
	return 0
}

// GetPublicKey returns nil for EdDSA as it uses different key type
func (c *frostConfigAdapter) GetPublicKey() *ecdsa.PublicKey {
	// FROST uses Ed25519/Schnorr, not ECDSA
	// This is a limitation of the current interface design
	// For Taproot, we could potentially convert but it's not standard ECDSA
	return nil
}

// GetPublicKeyBytes returns the public key as bytes
func (c *frostConfigAdapter) GetPublicKeyBytes() []byte {
	if c.isTaproot && c.taprootConfig != nil {
		return c.taprootConfig.PublicKey
	}
	if c.config != nil && c.config.PublicKey != nil {
		bytes, _ := c.config.PublicKey.MarshalBinary()
		return bytes
	}
	return nil
}

func (c *frostConfigAdapter) GetShare() *big.Int {
	if c.isTaproot && c.taprootConfig != nil {
		bytes, _ := c.taprootConfig.PrivateShare.MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	if c.config != nil && c.config.PrivateShare != nil {
		bytes, _ := c.config.PrivateShare.MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return nil
}

func (c *frostConfigAdapter) GetSharePublicKey() *ecdsa.PublicKey {
	// FROST uses Ed25519/Schnorr, not ECDSA
	return nil
}

func (c *frostConfigAdapter) GetPartyIDs() []string {
	if c.isTaproot && c.taprootConfig != nil {
		ids := make([]string, 0, len(c.taprootConfig.VerificationShares))
		for id := range c.taprootConfig.VerificationShares {
			ids = append(ids, string(id))
		}
		return ids
	}
	if c.config != nil && c.config.VerificationShares != nil {
		ids := make([]string, 0, len(c.config.VerificationShares.Points))
		for id := range c.config.VerificationShares.Points {
			ids = append(ids, string(id))
		}
		return ids
	}
	return nil
}

func (c *frostConfigAdapter) Serialize() ([]byte, error) {
	if c.isTaproot && c.taprootConfig != nil {
		return json.Marshal(c.taprootConfig)
	}
	if c.config != nil {
		return json.Marshal(c.config)
	}
	return nil, errors.New("no config to serialize")
}

// frostSignatureAdapter implements protocol.Signature for FROST
type frostSignatureAdapter struct {
	sig *frost.Signature
}

func (s *frostSignatureAdapter) GetR() *big.Int {
	// FROST signatures have an R point, convert X coordinate to big.Int
	if s.sig.R != nil && s.sig.R.XScalar() != nil {
		bytes, _ := s.sig.R.XScalar().MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return new(big.Int)
}

func (s *frostSignatureAdapter) GetS() *big.Int {
	// FROST signatures don't have a direct S component
	// This is a limitation of the current interface
	return new(big.Int)
}

func (s *frostSignatureAdapter) Verify(pubKey *ecdsa.PublicKey, message []byte) bool {
	// This adapter doesn't support ECDSA verification
	// FROST uses Schnorr signatures, not ECDSA
	return false
}

func (s *frostSignatureAdapter) Serialize() ([]byte, error) {
	// Marshal the signature using JSON for now
	return json.Marshal(s.sig)
}

// Helper functions

func convertToPartyIDs(ids []string) []party.ID {
	if ids == nil {
		return nil
	}
	result := make([]party.ID, len(ids))
	for i, id := range ids {
		result[i] = party.ID(id)
	}
	return result
}

func convertFromPartyIDs(ids []party.ID) []string {
	if ids == nil {
		return nil
	}
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = string(id)
	}
	return result
}

func toFROSTConfig(cfg protocol.KeyGenConfig) (*frost.Config, error) {
	// Try to cast directly first
	if adapter, ok := cfg.(*frostConfigAdapter); ok {
		if adapter.config != nil {
			return adapter.config, nil
		}
		// If it's a Taproot config, we need to convert it
		if adapter.taprootConfig != nil {
			// This would need proper conversion logic
			return nil, errors.New("cannot convert Taproot config to regular FROST config")
		}
	}

	// Otherwise, deserialize if possible
	data, err := cfg.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}

	// Try to unmarshal as FROST config
	config := frost.EmptyConfig(curve.Secp256k1{})
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal as FROST config: %w", err)
	}

	return config, nil
}
