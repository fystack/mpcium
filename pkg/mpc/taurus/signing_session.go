package taurus

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/fystack/mpcium/pkg/utils"
	"github.com/rs/zerolog"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

type SignSession interface {
	Session
}

type cggmp21SigningSession struct {
	session
	handler      *protocol.MultiHandler
	pool         *pool.Pool
	config       *config.Config
	signature    *ecdsa.Signature
	messagesCh   chan *protocol.Message
	resultMutex  sync.Mutex
	done         bool
	resultErr    error
	messageHash  []byte
	signerIDs    []party.ID
	useBroadcast bool
}

func newCGGMP21SigningSession(
	sessionID string,
	walletID string,
	messageHash []byte,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	signerIDs []party.ID,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	useBroadcast bool,
) (*cggmp21SigningSession, error) {
	// Load config from kvstore
	shareBytes, err := kvstore.Get(walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key share: %w", err)
	}

	config := &config.Config{}
	if err := json.Unmarshal(shareBytes, config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key share: %w", err)
	}

	// Create thread pool
	threadPool := pool.NewPool(0) // Use max threads

	return &cggmp21SigningSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           signerIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             5, // CGGMP21 signing has 5 rounds
			outCh:              make(chan msg, 100),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          config.Threshold,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         make(map[string]bool),
			processingLock:     sync.Mutex{},
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("sign:broadcast:cggmp21:%s", sessionID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("sign:direct:cggmp21:%s:%s", nodeID, sessionID)
				},
			},
			identityStore: identityStore,
		},
		pool:         threadPool,
		config:       config,
		messagesCh:   make(chan *protocol.Message, 100),
		messageHash:  messageHash,
		signerIDs:    signerIDs,
		useBroadcast: useBroadcast,
		done:         false,
	}, nil
}

func (s *cggmp21SigningSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Hex("messageHash", s.messageHash).
		Interface("signerIDs", s.signerIDs).
		Bool("useBroadcast", s.useBroadcast).
		Msg("Initializing CGGMP21 signing session")

	// Create CGGMP21 signing protocol
	startFunc := cmp.Sign(s.config, s.signerIDs, s.messageHash, s.pool)

	// Create handler
	handler, err := protocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		s.logger.Fatal().Err(err).Msg("Failed to create signing handler")
		return
	}

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("partyID", string(s.selfPartyID)).
		Interface("signerIDs", s.signerIDs).
		Msg("[INITIALIZED] CGGMP21 signing session initialized successfully")
}

func (s *cggmp21SigningSession) handleProtocolMessages() {
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
					s.signature = result.(*ecdsa.Signature)
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

func (s *cggmp21SigningSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	inboundMessage := &types.TaurusMessage{}
	if err := encoding.JsonBytesToStruct(msgBytes, inboundMessage); err != nil {
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

func (s *cggmp21SigningSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("ProcessOutboundMessage started: %s", s.sessionID)
	for {
		select {
		case m := <-s.outCh:
			// Convert party IDs back to strings
			recipientIDs := make([]string, len(m.ToPartyIDs))
			for i, pid := range m.ToPartyIDs {
				recipientIDs[i] = string(pid)
			}

			msgWireBytes := &types.TaurusMessage{
				SessionID:    s.sessionID,
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

func (s *cggmp21SigningSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		// failureEvent := event.CreateSignFailure(
		// 	s.sessionID,
		// 	s.walletID,
		// 	map[string]any{
		// 		"error": s.resultErr.Error(),
		// 	},
		// )
		// evtData, _ := encoding.StructToJsonBytes(failureEvent)
		// if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopic, s.walletID), evtData, nil); err != nil {
		// 	s.logger.Error().Err(err).Msg("failed to publish sign failure event")
		// }
		return
	}

	if s.signature == nil {
		s.logger.Error().Msg("No signature available after signing completion")
		return
	}

	// Verify signature
	if !s.signature.Verify(s.config.PublicPoint(), s.messageHash) {
		s.logger.Error().Msg("Failed to verify signature")
		// failureEvent := event.CreateSignFailure(
		// 	s.sessionID,
		// 	s.walletID,
		// 	map[string]any{
		// 		"error": "signature verification failed",
		// 	},
		// )
		// evtData, _ := encoding.StructToJsonBytes(failureEvent)
		// if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopic, s.walletID), evtData, nil); err != nil {
		// 	s.logger.Error().Err(err).Msg("failed to publish sign failure event")
		// }
		return
	}

	// Convert signature to hex
	sigRBytes, _ := s.signature.R.MarshalBinary()
	sigSBytes, _ := s.signature.S.MarshalBinary()
	sigR := hex.EncodeToString(sigRBytes)
	sigS := hex.EncodeToString(sigSBytes)

	// Publish success event
	// successEvent := event.CreateSignSuccess(
	// 	s.sessionID,
	// 	s.walletID,
	// 	sigR,
	// 	sigS,
	// 	map[string]any{
	// 		"messageHash": hex.EncodeToString(s.messageHash),
	// 		"signers":     len(s.signerIDs),
	// 		"protocol":    "CGGMP21",
	// 	},
	// )

	// evtData, _ := encoding.StructToJsonBytes(successEvent)
	// if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopic, s.walletID), evtData, nil); err != nil {
	// 	s.logger.Error().Err(err).Msg("failed to publish sign success event")
	// }

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Str("sigR", sigR).
		Str("sigS", sigS).
		Msg("CGGMP21 signing completed successfully")
}

func (s *cggmp21SigningSession) Stop() {
	if s.pool != nil {
		s.pool.TearDown()
	}
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *cggmp21SigningSession) WaitForFinish() string {
	return <-s.externalFinishChan
}
