package taurus

import (
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/taurusgroup/multi-party-sig/pkg/party"

	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
)

type SessionType string

const (
	TypeGenerateWalletResultFmt = "mpc.mpc_keygen_result.%s"
	TypeReshareWalletResultFmt  = "mpc.mpc_reshare_result.%s"

	SessionTypeCGGMP21 SessionType = "session_cggmp21"
	SessionTypeECDSA   SessionType = "ecdsa"
	SessionTypeEDDSA   SessionType = "eddsa"
)

var (
	ErrNotEnoughParticipants = errors.New("Not enough participants to sign")
	ErrNotInParticipantList  = errors.New("Node is not in the participant list")
)

type TopicComposer struct {
	ComposeBroadcastTopic func() string
	ComposeDirectTopic    func(nodeID string) string
}

type KeyComposerFn func(id string) string

type Session interface {
	ListenToIncomingMessageAsync(f func(msgBytes []byte))
	ErrChan() <-chan error
	Init()
	ProcessInboundMessage(msgBytes []byte)
	ProcessOutboundMessage()
	WaitForFinish() string
}

type session struct {
	walletID           string
	sessionID          string
	pubSub             messaging.PubSub
	selfPartyID        party.ID
	partyIDs           []party.ID
	subscriberList     []messaging.Subscription
	rounds             int
	outCh              chan msg
	errCh              chan error
	finishCh           chan bool
	externalFinishChan chan string
	threshold          int
	kvstore            kvstore.KVStore
	keyinfoStore       keyinfo.Store
	resultQueue        messaging.MessageQueue
	logger             zerolog.Logger
	processing         map[string]bool
	processingLock     sync.Mutex
	topicComposer      *TopicComposer
	identityStore      identity.Store
}

type msg struct {
	FromPartyID party.ID
	ToPartyIDs  []party.ID
	IsBroadcast bool
	Data        []byte
}

func (s *session) ProcessInboundMessage(msgBytes []byte) {
	// This should be implemented by specific session types
	// If this method is called directly on the base session type, it means
	// the concrete type doesn't properly implement ProcessInboundMessage
	panic("ProcessInboundMessage must be implemented by session type")
}

func (s *session) ListenToIncomingMessageAsync(f func(msgBytes []byte)) {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("Received broadcast message")
		f(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, broadcastSub)

	// Subscribe to direct messages
	directTopic := s.topicComposer.ComposeDirectTopic(string(s.selfPartyID))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("Received direct message")
		f(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Msg("Listening to incoming messages")
}

func (s *session) sendMsg(message *types.TaurusMessage) {
	data, err := encoding.StructToJsonBytes(message)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal message")
		return
	}

	if message.IsBroadcast {
		topic := s.topicComposer.ComposeBroadcastTopic()
		if err := s.pubSub.Publish(topic, data); err != nil {
			s.logger.Error().Err(err).Msgf("Failed to publish broadcast message to %s", topic)
		} else {
			s.logger.Debug().Str("topic", topic).Msg("Published broadcast message")
		}
	} else {
		// Send to specific recipients
		for _, recipient := range message.RecipientIDs {
			topic := s.topicComposer.ComposeDirectTopic(recipient)
			if err := s.pubSub.Publish(topic, data); err != nil {
				s.logger.Error().Err(err).Msgf("Failed to publish direct message to %s", topic)
			} else {
				s.logger.Debug().
					Str("topic", topic).
					Str("recipient", recipient).
					Msg("Published direct message")
			}
		}
	}
}

func (s *session) ErrChan() <-chan error {
	return s.errCh
}

func (s *session) unsubscribe() {
	for _, sub := range s.subscriberList {
		if err := sub.Unsubscribe(); err != nil {
			s.logger.Error().Err(err).Msg("Failed to unsubscribe")
		}
	}
	s.subscriberList = nil
}

func (s *session) Stop() {
	s.unsubscribe()
}

// Helper function to get party routing destination
func PartyIDToRoutingDest(partyID party.ID) string {
	// Extract node ID from party ID if it contains version info
	nodeID := string(partyID)
	// Simple extraction - in production you'd have more robust parsing
	return nodeID
}
