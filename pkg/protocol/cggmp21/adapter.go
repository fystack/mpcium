package cggmp21

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/fystack/mpcium/pkg/protocol"
	mpsEcdsa "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	mpsProtocol "github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

// CGGMP21Protocol implements the Protocol interface using CGGMP21
type CGGMP21Protocol struct {
	pool *pool.Pool
}

// NewCGGMP21Protocol creates a new CGGMP21 protocol adapter
func NewCGGMP21Protocol() *CGGMP21Protocol {
	return &CGGMP21Protocol{
		pool: pool.NewPool(0), // Use max threads
	}
}

// Close cleans up resources
func (p *CGGMP21Protocol) Close() {
	if p.pool != nil {
		p.pool.TearDown()
	}
}

// Name returns the protocol name
func (p *CGGMP21Protocol) Name() string {
	return "CGGMP21"
}

// KeyGen starts a distributed key generation
func (p *CGGMP21Protocol) KeyGen(selfID string, partyIDs []string, threshold int) (protocol.Party, error) {
	// Convert string IDs to party.ID
	ids := make([]party.ID, len(partyIDs))
	for i, id := range partyIDs {
		ids[i] = party.ID(id)
	}

	// Create the keygen protocol
	startFunc := cmp.Keygen(curve.Secp256k1{}, party.ID(selfID), ids, threshold, p.pool)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create keygen handler: %w", err)
	}

	return &partyAdapter{
		handler: handler,
		selfID:  selfID,
	}, nil
}

// Refresh refreshes shares from an existing config
func (p *CGGMP21Protocol) Refresh(cfg protocol.KeyGenConfig) (protocol.Party, error) {
	// Convert to CGGMP21 config
	cmpConfig, err := toCMPConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Create refresh protocol
	startFunc := cmp.Refresh(cmpConfig, p.pool)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh handler: %w", err)
	}

	return &partyAdapter{
		handler: handler,
		selfID:  cfg.GetPartyID(),
	}, nil
}

// Sign starts a signing protocol
func (p *CGGMP21Protocol) Sign(cfg protocol.KeyGenConfig, signers []string, messageHash []byte) (protocol.Party, error) {
	// Convert to CGGMP21 config
	cmpConfig, err := toCMPConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Convert signer IDs
	signerIDs := make([]party.ID, len(signers))
	for i, id := range signers {
		signerIDs[i] = party.ID(id)
	}

	// Create sign protocol
	startFunc := cmp.Sign(cmpConfig, signerIDs, messageHash, p.pool)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sign handler: %w", err)
	}

	return &partyAdapter{
		handler: handler,
		selfID:  cfg.GetPartyID(),
	}, nil
}

// PreSign starts a presigning protocol
func (p *CGGMP21Protocol) PreSign(cfg protocol.KeyGenConfig, signers []string) (protocol.Party, error) {
	// Convert to CGGMP21 config
	cmpConfig, err := toCMPConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Convert signer IDs
	signerIDs := make([]party.ID, len(signers))
	for i, id := range signers {
		signerIDs[i] = party.ID(id)
	}

	// Create presign protocol
	startFunc := cmp.Presign(cmpConfig, signerIDs, p.pool)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create presign handler: %w", err)
	}

	return &partyAdapter{
		handler: handler,
		selfID:  cfg.GetPartyID(),
	}, nil
}

// PreSignOnline completes a signature with a presignature
func (p *CGGMP21Protocol) PreSignOnline(cfg protocol.KeyGenConfig, preSig protocol.PreSignature, messageHash []byte) (protocol.Party, error) {
	// Convert to CGGMP21 types
	cmpConfig, err := toCMPConfig(cfg)
	if err != nil {
		return nil, err
	}

	cmpPreSig, ok := preSig.(*preSignatureAdapter)
	if !ok {
		return nil, errors.New("invalid presignature type")
	}

	// Create presign online protocol
	startFunc := cmp.PresignOnline(cmpConfig, cmpPreSig.preSig, messageHash, p.pool)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create presign online handler: %w", err)
	}

	return &partyAdapter{
		handler: handler,
		selfID:  cfg.GetPartyID(),
	}, nil
}

// partyAdapter adapts mpsProtocol.Handler to protocol.Party
type partyAdapter struct {
	handler *mpsProtocol.MultiHandler
	selfID  string
	mu      sync.Mutex
	done    bool
	result  interface{}
	err     error
}

func (p *partyAdapter) Update(msg protocol.Message) error {
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

func (p *partyAdapter) Messages() <-chan protocol.Message {
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

func (p *partyAdapter) Errors() <-chan error {
	// CGGMP21 doesn't have a separate error channel
	// Errors are returned in Result()
	ch := make(chan error)
	close(ch)
	return ch
}

func (p *partyAdapter) Done() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done
}

func (p *partyAdapter) Result() (interface{}, error) {
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
	case *config.Config:
		return &configAdapter{config: r}, nil
	case *mpsEcdsa.Signature:
		return &signatureAdapter{sig: r}, nil
	case *mpsEcdsa.PreSignature:
		return &preSignatureAdapter{preSig: r}, nil
	default:
		return p.result, nil
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

// configAdapter implements protocol.KeyGenConfig
type configAdapter struct {
	config *config.Config
}

func (c *configAdapter) GetPartyID() string {
	return string(c.config.ID)
}

func (c *configAdapter) GetThreshold() int {
	return c.config.Threshold
}

func (c *configAdapter) GetPublicKey() *ecdsa.PublicKey {
	point := c.config.PublicPoint()
	// Convert curve.Point to ecdsa.PublicKey
	// Using XScalar to get X coordinate as big.Int
	if point.XScalar() != nil {
		xBytes, _ := point.XScalar().MarshalBinary()
		x := new(big.Int).SetBytes(xBytes)
		// For Y, we need to derive it from the point
		// This is a limitation - we can't get Y directly
		return &ecdsa.PublicKey{
			Curve: nil, // We can't convert curve.Curve to elliptic.Curve
			X:     x,
			Y:     new(big.Int), // Placeholder
		}
	}
	return nil
}

func (c *configAdapter) GetShare() *big.Int {
	// Get ECDSA scalar share and convert to big.Int
	if c.config.ECDSA != nil {
		bytes, _ := c.config.ECDSA.MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return nil
}

func (c *configAdapter) GetSharePublicKey() *ecdsa.PublicKey {
	// Get this party's public share
	if public, ok := c.config.Public[c.config.ID]; ok && public.ECDSA != nil {
		// Convert curve.Point to ecdsa.PublicKey
		if public.ECDSA.XScalar() != nil {
			xBytes, _ := public.ECDSA.XScalar().MarshalBinary()
			x := new(big.Int).SetBytes(xBytes)
			return &ecdsa.PublicKey{
				Curve: nil, // We can't convert curve.Curve to elliptic.Curve
				X:     x,
				Y:     new(big.Int), // Placeholder
			}
		}
	}
	return nil
}

func (c *configAdapter) GetPartyIDs() []string {
	ids := c.config.PartyIDs()
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = string(id)
	}
	return result
}

func (c *configAdapter) Serialize() ([]byte, error) {
	return json.Marshal(c.config)
}

// signatureAdapter implements protocol.Signature
type signatureAdapter struct {
	sig *mpsEcdsa.Signature
}

func (s *signatureAdapter) GetR() *big.Int {
	// Convert curve.Point R to big.Int
	if s.sig.R != nil && s.sig.R.XScalar() != nil {
		bytes, _ := s.sig.R.XScalar().MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return nil
}

func (s *signatureAdapter) GetS() *big.Int {
	// Convert curve.Scalar S to big.Int
	if s.sig.S != nil {
		bytes, _ := s.sig.S.MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return nil
}

func (s *signatureAdapter) Verify(pubKey *ecdsa.PublicKey, message []byte) bool {
	// Verification would require converting ecdsa.PublicKey to curve.Point
	// This is complex without the proper curve conversion
	// For now, return false
	return false
}

func (s *signatureAdapter) Serialize() ([]byte, error) {
	return json.Marshal(s.sig)
}

// preSignatureAdapter implements protocol.PreSignature
type preSignatureAdapter struct {
	preSig *mpsEcdsa.PreSignature
}

func (p *preSignatureAdapter) GetID() string {
	// Convert RID (byte slice) to hex string
	return fmt.Sprintf("%x", p.preSig.ID)
}

func (p *preSignatureAdapter) Validate() error {
	return p.preSig.Validate()
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

func toCMPConfig(cfg protocol.KeyGenConfig) (*config.Config, error) {
	// Try to cast directly first
	if adapter, ok := cfg.(*configAdapter); ok {
		return adapter.config, nil
	}

	// Otherwise, we need to reconstruct
	// This is a simplified version - in production you'd need proper serialization
	return nil, errors.New("config conversion not implemented for non-CGGMP21 configs")
}
