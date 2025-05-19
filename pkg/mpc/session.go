package mpc

import (
	"fmt"
	"slices"
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

var (
	ErrNotEnoughParticipants = errors.New("Not enough participants to sign")
)

// SessionType constants
type SessionType string

const (
	SessionTypeEcdsa SessionType = "session_ecdsa"
	SessionTypeEddsa SessionType = "session_eddsa"
)

// Topic format constants
const (
	TopicFormatResharingBroadcast = "resharing:broadcast:%s:%s"
	TopicFormatResharingDirect    = "resharing:direct:%s:%s:%s"
)

// Key format constants
const (
	KeyFormatEcdsa = "ecdsa:%s"
	KeyFormatEddsa = "eddsa:%s"
)

type TopicComposer struct {
	ComposeBroadcastTopic func() string
	ComposeDirectTopic    func(nodeID string) string
}

type KeyComposerFn func(id string) string

type Session struct {
	walletID           string
	pubSub             messaging.PubSub
	direct             messaging.DirectMessaging
	threshold          int
	participantPeerIDs []string
	selfPartyID        *tss.PartyID
	// IDs of all parties in the session including self
	partyIDs []*tss.PartyID
	outCh    chan tss.Message
	ErrCh    chan error
	party    tss.Party

	// preParams is nil for EDDSA session
	preParams *keygen.LocalPreParams
	// reshareParams is nil for non resharing session
	reshareParams *tss.ReSharingParameters
	kvstore       kvstore.KVStore
	keyinfoStore  keyinfo.Store
	broadcastSub  messaging.Subscription
	directSub     messaging.Subscription
	resultQueue   messaging.MessageQueue
	identityStore identity.Store

	topicComposer *TopicComposer
	composeKey    KeyComposerFn
	getRoundFunc  GetRoundFunc
	mu            sync.Mutex
	// After the session is done, the key will be stored pubkeyBytes
	pubkeyBytes []byte
	sessionType SessionType
}

func (s *Session) PartyID() *tss.PartyID {
	return s.selfPartyID
}

func (s *Session) PartyIDs() []*tss.PartyID {
	return s.partyIDs
}

func (s *Session) PartyCount() int {
	return len(s.partyIDs)
}

func (s *Session) handleTssMessage(keyshare tss.Message) {
	data, routing, err := keyshare.WireBytes()
	if err != nil {
		s.ErrCh <- err
		return
	}
	tssMsg := types.NewTssMessage(s.walletID, data, routing.IsBroadcast, routing.From, routing.To)
	signature, err := s.identityStore.SignMessage(&tssMsg)
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

	if routing.IsBroadcast && len(routing.To) == 0 {
		err := s.pubSub.Publish(s.topicComposer.ComposeBroadcastTopic(), msg)
		if err != nil {
			s.ErrCh <- err
			return
		}
	} else {
		for _, to := range routing.To {
			nodeID := PartyIDToNodeID(to)
			topic := s.topicComposer.ComposeDirectTopic(nodeID)
			err := s.direct.Send(topic, msg)
			if err != nil {
				s.ErrCh <- fmt.Errorf("Failed to send direct message to %s: %w", topic, err)
			}

		}

	}
}

func (s *Session) handleResharingMessage(msg tss.Message) {
	data, routing, err := msg.WireBytes()
	if err != nil {
		s.ErrCh <- err
		return
	}

	tssMsg := types.NewTssResharingMessage(s.walletID, data, routing.IsBroadcast, routing.From, routing.To, routing.IsToOldCommittee, routing.IsToOldAndNewCommittees)
	signature, err := s.identityStore.SignMessage(&tssMsg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to sign message: %w", err)
		return
	}
	tssMsg.Signature = signature
	msgBytes, err := types.MarshalTssMessage(&tssMsg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to marshal tss message: %w", err)
		return
	}

	// Just send to all intended recipients except self
	for _, to := range routing.To {
		if to.Id != s.selfPartyID.Id {
			s.direct.Send(s.topicComposer.ComposeDirectTopic(PartyIDToNodeID(to)), msgBytes)
		}
	}
}

func (s *Session) receiveTssMessage(rawMsg []byte) {
	msg, err := types.UnmarshalTssMessage(rawMsg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to unmarshal message: %w", err)
		return
	}
	err = s.identityStore.VerifyMessage(msg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to verify message: %w, tampered message", err)
		return
	}

	toIDs := make([]string, len(msg.To))
	for i, id := range msg.To {
		toIDs[i] = id.String()
	}

	round, err := s.getRoundFunc(msg.MsgBytes, s.selfPartyID, msg.IsBroadcast)
	if err != nil {
		s.ErrCh <- errors.Wrap(err, "Broken TSS Share")
		return
	}

	logger.Info(fmt.Sprintf("%s Received message", s.sessionType),
		"from", msg.From.String(),
		"to", strings.Join(toIDs, ","),
		"isBroadcast", msg.IsBroadcast,
		"round", round.RoundMsg)

	isBroadcast := msg.IsBroadcast && len(msg.To) == 0
	isToSelf := len(msg.To) == 1 && ComparePartyIDs(msg.To[0], s.selfPartyID)

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

func (s *Session) receiveTssResharingMessage(rawMsg []byte) {
	msg, err := types.UnmarshalTssMessage(rawMsg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to unmarshal message: %w", err)
		return
	}
	err = s.identityStore.VerifyMessage(msg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to verify message: %w, tampered message", err)
		return
	}

	toIDs := make([]string, len(msg.To))
	for i, id := range msg.To {
		toIDs[i] = id.String()
	}
	round, err := s.getRoundFunc(msg.MsgBytes, s.selfPartyID, msg.IsBroadcast)
	if err != nil {
		s.ErrCh <- errors.Wrap(err, "Broken TSS Share")
		return
	}

	logger.Info(fmt.Sprintf("%s Received resharing message", s.sessionType),
		"from", msg.From.String(),
		"to", strings.Join(toIDs, ","),
		"isBroadcast", msg.IsBroadcast,
		"round", round.RoundMsg)

	isToSelf := slices.Contains(toIDs, s.selfPartyID.String())
	if isToSelf {
		s.mu.Lock()
		defer s.mu.Unlock()
		ok, err := s.party.UpdateFromBytes(msg.MsgBytes, msg.From, msg.IsBroadcast)
		if !ok || err != nil {
			logger.Error("Failed to update party", err, "walletID", s.walletID)
			return
		}
	}
}

func (s *Session) SendReplySignSuccess(natMsg *nats.Msg) {
	msg := natMsg.Data
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.pubSub.Publish(natMsg.Reply, msg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to reply sign sucess message: %w", err)
		return
	}
	logger.Info("Sent reply sign sucess message", "reply", natMsg.Reply)
}

func (s *Session) ListenToIncomingMessageAsync() {
	go func() {
		sub, err := s.pubSub.Subscribe(s.topicComposer.ComposeBroadcastTopic(), func(natMsg *nats.Msg) {
			msg := natMsg.Data
			s.receiveTssMessage(msg)
		})

		if err != nil {
			s.ErrCh <- fmt.Errorf("Failed to subscribe to broadcast topic %s: %w", s.topicComposer.ComposeBroadcastTopic(), err)
			return
		}

		s.broadcastSub = sub
	}()

	nodeID := PartyIDToNodeID(s.selfPartyID)
	targetID := s.topicComposer.ComposeDirectTopic(nodeID)
	sub, err := s.direct.Listen(targetID, func(msg []byte) {
		go s.receiveTssMessage(msg) // async for avoid timeout
	})
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to subscribe to direct topic %s: %w", targetID, err)
	}
	s.directSub = sub

}

func (s *Session) ListenToIncomingResharingMessageAsync() {
	nodeID := PartyIDToNodeID(s.selfPartyID)
	targetID := s.topicComposer.ComposeDirectTopic(nodeID)
	sub, err := s.direct.Listen(targetID, func(msg []byte) {
		go s.receiveTssResharingMessage(msg) // async for avoid timeout
	})
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to subscribe to direct topic %s: %w", targetID, err)
	}
	s.directSub = sub
}

func (s *Session) Close() error {
	if s.broadcastSub != nil {
		err := s.broadcastSub.Unsubscribe()
		if err != nil {
			return err
		}
	}
	if s.directSub != nil {
		err := s.directSub.Unsubscribe()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) GetPubKeyResult() []byte {
	return s.pubkeyBytes
}

func (s *Session) ErrChan() <-chan error {
	return s.ErrCh
}

// SaveKeyInfo saves the key info with resharing information
func (s *Session) SaveKeyInfo(isReshared bool) error {
	keyInfo := &keyinfo.KeyInfo{
		ParticipantPeerIDs: s.participantPeerIDs,
		Threshold:          s.threshold,
		IsReshared:         isReshared,
	}

	err := s.keyinfoStore.Save(s.composeKey(s.walletID), keyInfo)
	if err != nil {
		logger.Error("Failed to save keyinfo", err, "walletID", s.walletID)
		return err
	}
	return nil
}

// SaveKeyData saves the key data to the kvstore
func (s *Session) SaveKeyData(keyBytes []byte) error {
	err := s.kvstore.Put(s.composeKey(s.walletID), keyBytes)
	if err != nil {
		logger.Error("Failed to save key", err, "walletID", s.walletID)
		return err
	}
	return nil
}
