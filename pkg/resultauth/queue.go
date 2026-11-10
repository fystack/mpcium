package resultauth

import (
	"maps"

	"github.com/fystack/mpcium/pkg/messaging"
)

type signingQueue struct {
	messaging.MessageQueue
	signer Signer
	nodeID string
}

// NewSigningQueue wraps a result queue so every enqueued result carries this node's signature headers.
func NewSigningQueue(queue messaging.MessageQueue, signer Signer, nodeID string) messaging.MessageQueue {
	return &signingQueue{MessageQueue: queue, signer: signer, nodeID: nodeID}
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
	headers := make(map[string]string, len(signedOptions.Headers)+len(signatureHeaders))
	maps.Copy(headers, signedOptions.Headers)
	maps.Copy(headers, signatureHeaders)
	signedOptions.Headers = headers

	return q.MessageQueue.Enqueue(topic, message, &signedOptions)
}
