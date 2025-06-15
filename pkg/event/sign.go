package event

const (
	SigningPublisherStream     = "mpc-signing"
	SigningConsumerStream      = "mpc-signing-consumer"
	SigningRequestTopic        = "mpc.signing_request.*"
	SigningResultTopic         = "mpc.signing_result.*"
	SigningResultCompleteTopic = "mpc.signing_result.complete"
	MPCSigningEventTopic       = "mpc:sign"
	SigningRequestEventTopic   = "mpc.signing_request.event"
)

type SigningResultType int

const (
	SigningResultTypeUnknown SigningResultType = iota
	SigningResultTypeSuccess
	SigningResultTypeError
)
