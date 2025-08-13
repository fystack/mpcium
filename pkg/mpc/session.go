package mpc

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

type SessionType string

const (
	TypeGenerateWalletResultFmt = "mpc.mpc_keygen_result.%s"
	TypeReshareWalletResultFmt  = "mpc.mpc_reshare_result.%s"
	TypeSigningResultFmt        = "mpc.mpc_signing_result.%s"

	SessionTypeECDSA SessionType = "session_ecdsa"
	SessionTypeEDDSA SessionType = "session_eddsa"
)

var (
	ErrNotEnoughParticipants = errors.New("Not enough participants to sign")
	ErrNotInParticipantList  = errors.New("Node is not in the participant list")
)

type TopicComposer struct {
	ComposeBroadcastTopic func() string
	ComposeDirectTopic    func(fromID string, toID string) string
}

type KeyComposerFn func(id string) string

type Session interface {
	ListenToIncomingMessageAsync()
	ListenToPeersAsync(peerIDs []string)
	ErrChan() <-chan error
}

type session struct {
	walletID string
	pubSub   messaging.PubSub
	direct   messaging.DirectMessaging

	threshold          int
	participantPeerIDs []string
	selfPartyID        *tss.PartyID
	// IDs of all parties in the session including self
	partyIDs []*tss.PartyID
	outCh    chan tss.Message
	ErrCh    chan error
	party    tss.Party
	version  int

	// preParams is nil for EDDSA session
	preParams    *keygen.LocalPreParams
	kvstore      kvstore.KVStore
	keyinfoStore keyinfo.Store
	broadcastSub messaging.Subscription
	directSubs   []messaging.Subscription

	resultQueue   messaging.MessageQueue
	identityStore identity.Store

	topicComposer *TopicComposer
	composeKey    KeyComposerFn
	getRoundFunc  GetRoundFunc
	mu            sync.Mutex
	// After the session is done, the key will be stored pubkeyBytes
	pubkeyBytes   []byte
	sessionType   SessionType
	idempotentKey string
}

func (s *session) PartyID() *tss.PartyID {
	return s.selfPartyID
}

func (s *session) PartyIDs() []*tss.PartyID {
	return s.partyIDs
}

func (s *session) PartyCount() int {
	return len(s.partyIDs)
}

// update: use AEAD encryption for each message so NATs server learns nothing
func (s *session) handleTssMessage(keyshare tss.Message) {
	data, routing, err := keyshare.WireBytes()
	if err != nil {
		s.ErrCh <- err
		return
	}

	tssMsg := types.NewTssMessage(s.walletID, data, routing.IsBroadcast, routing.From, routing.To)

	toIDs := make([]string, len(routing.To))
	for i, id := range routing.To {
		toIDs[i] = id.String()
	}
	logger.Debug(
		fmt.Sprintf("%s Sending message", s.sessionType),
		"from",
		s.selfPartyID.String(),
		"to",
		toIDs,
		"isBroadcast",
		routing.IsBroadcast,
	)

	// Broadcast message
	if routing.IsBroadcast && len(routing.To) == 0 {
		signature, err := s.identityStore.SignMessage(&tssMsg) // attach signature
		if err != nil {
			s.ErrCh <- fmt.Errorf("failed to sign message: %w", err)
			return
		}
		tssMsg.Signature = signature
		msg, err := types.MarshalTssMessage(&tssMsg)
		if err != nil {
			s.ErrCh <- fmt.Errorf("failed to marshal tss message: %w", err)
			return
		}

		err = s.pubSub.Publish(s.topicComposer.ComposeBroadcastTopic(), msg)
		if err != nil {
			s.ErrCh <- err
			return
		}
	} else {
		// p2p message
		msg, err := types.MarshalTssMessage(&tssMsg) // without signature
		if err != nil {
			s.ErrCh <- fmt.Errorf("failed to marshal tss message: %w", err)
			return
		}

		selfID := partyIDToNodeID(s.selfPartyID)
		for _, to := range routing.To {
			toNodeID := partyIDToNodeID(to)
			topic := s.topicComposer.ComposeDirectTopic(selfID, toNodeID)
			if selfID == toNodeID {
				err := s.direct.SendToSelf(topic, msg)
				if err != nil {
					logger.Error("Failed in SendToSelf direct message", err, "topic", topic)
					s.ErrCh <- fmt.Errorf("failed to send direct message to %s", topic)
				}
			} else {
				cipher, err := s.identityStore.EncryptMessage(msg, toNodeID)
				if err != nil {
					s.ErrCh <- fmt.Errorf("encrypt tss message error %w", err)
					logger.Error("Encrypt tss message error", err, "topic", topic)
				}
				err = s.direct.SendToOther(topic, cipher)
				if err != nil {
					logger.Error("Failed in SendToOther direct message", err, "topic", topic)
					s.ErrCh <- fmt.Errorf("failed to send direct message to %w", err)
				}
			}
		}
	}
}

func (s *session) receiveP2PTssMessage(topic string, cipher []byte) {
	senderID := extractSenderIDFromDirectTopic(topic)
	if senderID == "" {
		s.ErrCh <- fmt.Errorf("failed to extract senderID from direct topic: the direct topic format is wrong")
		return
	}

	var plaintext []byte
	var err error

	if senderID == partyIDToNodeID(s.selfPartyID) {
		plaintext = cipher // to self, no decryption needed
	} else {
		plaintext, err = s.identityStore.DecryptMessage(cipher, senderID)
		if err != nil {
			s.ErrCh <- fmt.Errorf("failed to decrypt message: %w, tampered message", err)
			return
		}
	}
	msg, err := types.UnmarshalTssMessage(plaintext)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to unmarshal message: %w", err)
		return
	}

	s.receiveTssMessage(msg)
}

func (s *session) receiveBroadcastTssMessage(rawMsg []byte) {

	msg, err := types.UnmarshalTssMessage(rawMsg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to unmarshal message: %w", err)
		return
	}

	err = s.identityStore.VerifyMessage(msg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to verify message: %w, tampered message", err)
		return
	}

	s.receiveTssMessage(msg)
}

// update: the logic of receiving message should be modified
func (s *session) receiveTssMessage(msg *types.TssMessage) {
	toIDs := make([]string, len(msg.To))
	for i, id := range msg.To {
		toIDs[i] = id.String()
	}

	round, err := s.getRoundFunc(msg.MsgBytes, s.selfPartyID, msg.IsBroadcast)
	if err != nil {
		s.ErrCh <- errors.Wrap(err, "Broken TSS Share")
		return
	}
	logger.Debug(
		"Received message",
		"round",
		round.RoundMsg,
		"isBroadcast",
		msg.IsBroadcast,
		"to",
		toIDs,
		"from",
		msg.From.String(),
		"self",
		s.selfPartyID.String(),
	)
	isBroadcast := msg.IsBroadcast && len(msg.To) == 0
	var isToSelf bool
	for _, to := range msg.To {
		if comparePartyIDs(to, s.selfPartyID) {
			isToSelf = true
			break
		}
	}

	if isBroadcast || isToSelf {
		s.mu.Lock()
		defer s.mu.Unlock()
		ok, err := s.party.UpdateFromBytes(msg.MsgBytes, msg.From, msg.IsBroadcast)
		if !ok || err != nil {
			logger.Error("Failed to update party", err, "walletID", s.walletID)
			return
		}
	}
}

func (s *session) subscribeDirectTopicAsync(topic string) error {
	t := topic // avoid capturing the changing loop variable
	sub, err := s.direct.Listen(t, func(cipher []byte) {
		// async to avoid timeouts in handlers
		go s.receiveP2PTssMessage(t, cipher)
	})
	if err != nil {
		return fmt.Errorf("Failed to subscribe to direct topic %s: %w", t, err)
	}
	s.directSubs = append(s.directSubs, sub)
	return nil
}

func (s *session) subscribeFromPeersAsync(fromIDs []string) {
	toID := partyIDToNodeID(s.selfPartyID)
	for _, fromID := range fromIDs {
		topic := s.topicComposer.ComposeDirectTopic(fromID, toID)
		if err := s.subscribeDirectTopicAsync(topic); err != nil {
			s.ErrCh <- err
		}
	}
}

func (s *session) subscribeBroadcastAsync() {
	go func() {
		topic := s.topicComposer.ComposeBroadcastTopic()
		sub, err := s.pubSub.Subscribe(topic, func(natMsg *nats.Msg) {
			s.receiveBroadcastTssMessage(natMsg.Data)
		})
		if err != nil {
			s.ErrCh <- fmt.Errorf("Failed to subscribe to broadcast topic %s: %w", topic, err)
			return
		}
		s.broadcastSub = sub
	}()
}

func (s *session) ListenToIncomingMessageAsync() {
	// 1) broadcast
	s.subscribeBroadcastAsync()

	// 2) direct from peers in this session's partyIDs (includes self)
	s.subscribeFromPeersAsync(partyIDsToNodeIDs(s.partyIDs))
}

func (s *session) ListenToPeersAsync(peerIDs []string) {
	s.subscribeFromPeersAsync(peerIDs)
}

func (s *session) Close() error {
	err := s.broadcastSub.Unsubscribe()
	if err != nil {
		return err
	}

	for _, sub := range s.directSubs {
		err = sub.Unsubscribe()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *session) GetPubKeyResult() []byte {
	return s.pubkeyBytes
}

func (s *session) ErrChan() <-chan error {
	return s.ErrCh
}

func (s *session) GetVersion() int {
	return s.version
}

// loadOldShareDataGeneric loads the old share data from kvstore with backward compatibility (versioned and unversioned keys)
func (s *session) loadOldShareDataGeneric(walletID string, version int, dest interface{}) error {
	var (
		key     string
		keyData []byte
		err     error
	)

	// Try versioned key first if version > 0
	if version > 0 {
		key = s.composeKey(walletIDWithVersion(walletID, version))
		keyData, err = s.kvstore.Get(key)
		if err != nil {
			return err
		}
	}

	// If version == 0 or previous key not found, fall back to unversioned key
	if version == 0 {
		key = s.composeKey(walletID)
		keyData, err = s.kvstore.Get(key)
		if err != nil {
			return err
		}
	}

	if err != nil {
		return fmt.Errorf("failed to get wallet data from KVStore (key=%s): %w", key, err)
	}

	if err := json.Unmarshal(keyData, dest); err != nil {
		return fmt.Errorf("failed to unmarshal wallet data: %w", err)
	}
	return nil
}

// walletIDWithVersion is used to compose the key for the kvstore
func walletIDWithVersion(walletID string, version int) string {
	if version > 0 {
		return fmt.Sprintf("%s_v%d", walletID, version)
	}
	return walletID
}

func extractSenderIDFromDirectTopic(topic string) string {
	// E.g: keygen:direct:ecdsa:<fromID>:<toID>:<walletID>
	parts := strings.SplitN(topic, ":", 5)
	if len(parts) >= 4 {
		return parts[3]
	}

	return ""
}
