package taurus

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/fystack/mpcium/pkg/utils"
	"github.com/rs/zerolog"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

type KeyGenSession interface {
	Session
}

type cggmp21KeygenSession struct {
	session
	handler     *protocol.MultiHandler
	pool        *pool.Pool
	config      *config.Config
	messagesCh  chan *protocol.Message
	resultMutex sync.Mutex
	done        bool
	resultErr   error
}

func NewCGGMP21KeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *cggmp21KeygenSession {
	// Create thread pool
	threadPool := pool.NewPool(0) // Use max threads

	return &cggmp21KeygenSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             5, // CGGMP21 keygen has 5 rounds
			outCh:              make(chan msg, 100),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          threshold,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         make(map[string]bool),
			processingLock:     sync.Mutex{},
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("keygen:broadcast:cggmp21:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("keygen:direct:cggmp21:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		pool:       threadPool,
		messagesCh: make(chan *protocol.Message, 100),
		done:       false,
	}
}

func (s *cggmp21KeygenSession) Init() {
	s.logger.Info().
		Int("threshold", s.threshold).
		Interface("partyIDs", s.partyIDs).
		Msg("Initializing CGGMP21 keygen session")

	// Create CGGMP21 keygen protocol
	startFunc := cmp.Keygen(curve.Secp256k1{}, s.selfPartyID, s.partyIDs, s.threshold, s.pool)

	// Create handler
	handler, err := protocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		s.logger.Fatal().Err(err).Msg("Failed to create keygen handler")
		return
	}

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Interface("peerIDs", s.partyIDs).
		Str("walletID", s.walletID).
		Msg("[INITIALIZED] CGGMP21 keygen session initialized successfully")
}

func (s *cggmp21KeygenSession) handleProtocolMessages() {
	for {
		select {
		case protoMsg, ok := <-s.handler.Listen():
			if !ok {
				// Protocol finished
				s.resultMutex.Lock()
				s.done = true
				result, err := s.handler.Result()
				if err != nil {
					s.resultErr = err
					s.errCh <- err
				} else {
					s.config = result.(*config.Config)
				}
				s.resultMutex.Unlock()
				s.finishCh <- true
				return
			}

			// Convert protocol message to our message format
			var toPartyIDs []party.ID
			if !protoMsg.Broadcast && protoMsg.To != "" {
				toPartyIDs = []party.ID{protoMsg.To}
			}
			outMsg := msg{
				FromPartyID: protoMsg.From,
				ToPartyIDs:  toPartyIDs,
				IsBroadcast: protoMsg.Broadcast,
				Data:        protoMsg.Data,
			}

			s.outCh <- outMsg

		case protoMsg := <-s.messagesCh:
			// Handle incoming message
			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().Msgf("Handler cannot accept message from %s", protoMsg.From)
				continue
			}

			s.handler.Accept(protoMsg)
		}
	}
}

func (s *cggmp21KeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	inboundMessage := &types.TaurusMessage{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("ProcessInboundMessage unmarshal error")
		return
	}

	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(msgBytes))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	// Convert to protocol message
	protoMsg := &protocol.Message{
		From:      party.ID(inboundMessage.SenderID),
		To:        party.ID(""), // Single recipient for protocol messages
		Data:      inboundMessage.Body,
		Broadcast: inboundMessage.IsBroadcast,
	}

	// Send to handler
	s.messagesCh <- protoMsg
}

func (s *cggmp21KeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("ProcessOutboundMessage started: %s", s.walletID)
	for {
		select {
		case m := <-s.outCh:
			// Convert party IDs back to strings
			recipientIDs := make([]string, len(m.ToPartyIDs))
			for i, pid := range m.ToPartyIDs {
				recipientIDs[i] = string(pid)
			}

			msgWireBytes := &types.TaurusMessage{
				SessionID:    s.walletID,
				SenderID:     string(m.FromPartyID),
				RecipientIDs: recipientIDs,
				Body:         m.Data,
				IsBroadcast:  m.IsBroadcast,
			}

			s.sendMsg(msgWireBytes)

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *cggmp21KeygenSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		// failureEvent := event.CreateKeygenFailure(
		// 	s.walletID,
		// 	map[string]any{
		// 		"error": s.resultErr.Error(),
		// 	},
		// )
		// evtData, _ := json.Marshal(failureEvent)
		// if err := s.resultQueue.Enqueue(fmt.Sprintf("mpc.keygen_result.%s", s.walletID), evtData, nil); err != nil {
		// 	s.logger.Error().Err(err).Msg("failed to publish keygen failure event")
		// }
		return
	}

	if s.config == nil {
		s.logger.Error().Msg("No config available after keygen completion")
		return
	}

	// Save key share
	shareBytes, err := json.Marshal(s.config)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal key share")
		return
	}

	if err := s.kvstore.Put(s.walletID, shareBytes); err != nil {
		s.logger.Error().Err(err).Msgf("Failed to save key share for wallet %s", s.walletID)
		return
	}

	// Convert public key to hex
	// Use the X coordinate as a simple representation
	var pubKeyHex string
	if s.config != nil && s.config.PublicPoint() != nil {
		if xScalar := s.config.PublicPoint().XScalar(); xScalar != nil {
			xBytes, _ := xScalar.MarshalBinary()
			pubKeyHex = fmt.Sprintf("%x", xBytes)
		}
	}

	// Save key info
	keyInfo := &keyinfo.KeyInfo{
		ParticipantPeerIDs: convertFromPartyIDs(s.partyIDs),
		Threshold:          s.threshold,
		Version:            1,
	}

	if err := s.keyinfoStore.Save(s.walletID, keyInfo); err != nil {
		s.logger.Error().Err(err).Msgf("Failed to save key info for wallet %s", s.walletID)
		return
	}

	// Publish success event
	// successEvent := event.CreateKeygenSuccess(
	// 	s.walletID,
	// 	pubKeyHex,
	// 	map[string]any{
	// 		"threshold": s.threshold,
	// 		"parties":   len(s.partyIDs),
	// 		"protocol":  "CGGMP21",
	// 	},
	// )

	// evtData, _ := json.Marshal(successEvent)
	// if err := s.resultQueue.Enqueue(fmt.Sprintf("mpc.keygen_result.%s", s.walletID), evtData, nil); err != nil {
	// 	s.logger.Error().Err(err).Msg("failed to publish keygen success event")
	// }

	s.logger.Info().
		Str("walletID", s.walletID).
		Str("publicKey", pubKeyHex).
		Msg("CGGMP21 keygen completed successfully")
}

func (s *cggmp21KeygenSession) Stop() {
	if s.pool != nil {
		s.pool.TearDown()
	}
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *cggmp21KeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// Helper functions
func convertToPartyIDs(ids []string) []party.ID {
	result := make([]party.ID, len(ids))
	for i, id := range ids {
		result[i] = party.ID(id)
	}
	return result
}

func convertFromPartyIDs(ids []party.ID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = string(id)
	}
	return result
}
