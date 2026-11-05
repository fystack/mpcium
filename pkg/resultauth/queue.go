package resultauth

import (
	"maps"

	"github.com/fystack/mpcium/pkg/messaging"
)

type QueueOptions struct {
	// PerNodeResults keeps every node's copy of a result so clients can count t+1 signatures.
	PerNodeResults bool
}

type signingQueue struct {
	messaging.MessageQueue
	signer Signer
	nodeID string
	opts   QueueOptions
}

// NewSigningQueue wraps a result queue so every enqueued result carries this node's signature headers.
func NewSigningQueue(queue messaging.MessageQueue, signer Signer, nodeID string, opts QueueOptions) messaging.MessageQueue {
	return &signingQueue{MessageQueue: queue, signer: signer, nodeID: nodeID, opts: opts}
}

func (q *signingQueue) Enqueue(topic string, message []byte, options *messaging.EnqueueOptions) error {
	signatureHeaders, err := SignHeaders(q.signer, q.nodeID, topic, message)
	if err != nil {
		return err
	}

	signedOptions := messaging.EnqueueOptions{}
	if options != nil {
		signedOptions = *options
	}
	if q.opts.PerNodeResults && signedOptions.IdempotententKey != "" {
		signedOptions.IdempotententKey += ":" + q.nodeID
	}
	headers := make(map[string]string, len(signedOptions.Headers)+len(signatureHeaders))
	maps.Copy(headers, signedOptions.Headers)
	maps.Copy(headers, signatureHeaders)
	signedOptions.Headers = headers

	return q.MessageQueue.Enqueue(topic, message, &signedOptions)
}
