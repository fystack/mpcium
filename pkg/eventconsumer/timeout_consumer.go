package eventconsumer

import (
	"encoding/json"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/nats-io/nats.go"
)

// Other service not listen to this subject that make loss of message
const maxDeliveriesExceededSubject = "$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES.>"

type timeOutConsumer struct {
	natsConn      *nats.Conn
	resultQueue   messaging.MessageQueue
	identityStore identity.Store
	advisorySub   messaging.Subscription
}

func NewTimeOutConsumer(natsConn *nats.Conn, resultQueue messaging.MessageQueue, identityStore identity.Store) *timeOutConsumer {
	return &timeOutConsumer{
		natsConn:      natsConn,
		resultQueue:   resultQueue,
		identityStore: identityStore,
	}
}

func (tc *timeOutConsumer) Run() {
	logger.Info("Starting advisory consumer for max deliveries exceeded")
	sub, err := tc.natsConn.Subscribe(maxDeliveriesExceededSubject, func(msg *nats.Msg) {
		data := msg.Data
		var advisory struct {
			Stream    string `json:"stream"`
			StreamSeq uint64 `json:"stream_seq"`
		}

		err := json.Unmarshal(data, &advisory)
		if err != nil {
			logger.Error("Failed to unmarshal advisory message", err)
			return
		}
		logger.Info("Received advisory message", "stream", advisory.Stream, "stream_seq", advisory.StreamSeq)

		if advisory.Stream == event.SigningPublisherStream {
			logger.Info("Received max deliveries exceeded advisory", "stream", advisory.Stream, "stream_seq", advisory.StreamSeq)
			js, _ := tc.natsConn.JetStream()
			failedMsg, err := js.GetMsg(advisory.Stream, advisory.StreamSeq)

			if err != nil {
				logger.Error("Failed to retrieve message", err)
				return
			}

			data := failedMsg.Data
			var signErrorResult event.SigningResultEvent
			err = json.Unmarshal(data, &signErrorResult)

			if err != nil {
				logger.Error("Failed to unmarshal signing result event", err)
				return
			}

			signErrorResult.ResultType = event.ResultTypeError
			signErrorResult.ErrorCode = event.ErrorCodeMaxDeliveryAttempts
			signErrorResult.IsTimeout = true
			signErrorResult.ErrorReason = "Signing failed: maximum delivery attempts exceeded"

			if err := event.SignNodeResult(&signErrorResult, tc.identityStore); err != nil {
				logger.Error("Failed to sign signing result event", err, "txID", signErrorResult.TxID)
				return
			}

			signErrorResultBytes, err := json.Marshal(signErrorResult)
			if err != nil {
				logger.Error("Failed to marshal signing result event", err)
				return
			}

			err = tc.resultQueue.Enqueue(event.SigningResultTopic, signErrorResultBytes, &messaging.EnqueueOptions{
				IdempotententKey: event.NodeScopedIdempotentKey(signErrorResult.TxID, signErrorResult.NodeID),
			})
			if err != nil {
				logger.Error("Failed to publish signing result event", err)
				return
			}
			logger.Info("Published signing result event for timeout", "txID", signErrorResult.TxID)
			return
		}
	})
	if err != nil {
		logger.Error("Failed to subscribe to max deliveries exceeded subject", err)
		return
	}

	tc.advisorySub = sub
}

func (tc *timeOutConsumer) Close() error {
	err := tc.advisorySub.Unsubscribe()
	if err != nil {
		return err
	}
	return nil
}
