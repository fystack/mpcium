package event

import "strings"

type ResultType string

const (
	ResultTypeSuccess ResultType = "success"
	ResultTypeError   ResultType = "error"
)

// ErrorCode defines specific error types that can occur in MPC operations
type ErrorCode string

const (
	// Generic/Unknown errors
	ErrorCodeUnknown ErrorCode = "ERROR_UNKNOWN"

	// Network and connectivity errors
	ErrorCodeNetworkTimeout      ErrorCode = "ERROR_NETWORK_TIMEOUT"
	ErrorCodeNetworkConnection   ErrorCode = "ERROR_NETWORK_CONNECTION"
	ErrorCodeNetworkSubscription ErrorCode = "ERROR_NETWORK_SUBSCRIPTION"
	ErrorCodeMessageRouting      ErrorCode = "ERROR_MESSAGE_ROUTING"
	ErrorCodeDirectMessaging     ErrorCode = "ERROR_DIRECT_MESSAGING"

	// Session errors
	ErrorCodeSessionTimeout        ErrorCode = "ERROR_SESSION_TIMEOUT"
	ErrorCodeSessionCreation       ErrorCode = "ERROR_SESSION_CREATION"
	ErrorCodeSessionInitialization ErrorCode = "ERROR_SESSION_INITIALIZATION"
	ErrorCodeSessionCleanup        ErrorCode = "ERROR_SESSION_CLEANUP"
	ErrorCodeSessionDuplicate      ErrorCode = "ERROR_SESSION_DUPLICATE"
	ErrorCodeSessionStale          ErrorCode = "ERROR_SESSION_STALE"

	// Participant and peer errors
	ErrorCodeInsufficientParticipants ErrorCode = "ERROR_INSUFFICIENT_PARTICIPANTS"
	ErrorCodeIncompatiblePeerIDs      ErrorCode = "ERROR_INCOMPATIBLE_PEER_IDS"
	ErrorCodePeerNotReady             ErrorCode = "ERROR_PEER_NOT_READY"
	ErrorCodePeerUnavailable          ErrorCode = "ERROR_PEER_UNAVAILABLE"
	ErrorCodeParticipantNotFound      ErrorCode = "ERROR_PARTICIPANT_NOT_FOUND"

	// Key management errors
	ErrorCodeKeyNotFound      ErrorCode = "ERROR_KEY_NOT_FOUND"
	ErrorCodeKeyAlreadyExists ErrorCode = "ERROR_KEY_ALREADY_EXISTS"
	ErrorCodeKeyGeneration    ErrorCode = "ERROR_KEY_GENERATION"
	ErrorCodeKeySave          ErrorCode = "ERROR_KEY_SAVE"
	ErrorCodeKeyLoad          ErrorCode = "ERROR_KEY_LOAD"
	ErrorCodeKeyInfoSave      ErrorCode = "ERROR_KEY_INFO_SAVE"
	ErrorCodeKeyInfoLoad      ErrorCode = "ERROR_KEY_INFO_LOAD"
	ErrorCodeKeyEncoding      ErrorCode = "ERROR_KEY_ENCODING"
	ErrorCodeKeyDecoding      ErrorCode = "ERROR_KEY_DECODING"
	ErrorCodeMsgValidation    ErrorCode = "ERROR_MSG_VALIDATION"

	// Cryptographic operation errors
	ErrorCodeSignatureGeneration       ErrorCode = "ERROR_SIGNATURE_GENERATION"
	ErrorCodeSignatureVerification     ErrorCode = "ERROR_SIGNATURE_VERIFICATION"
	ErrorCodeInvalidInitiatorSignature ErrorCode = "ERROR_INVALID_INITIATOR_SIGNATURE"
	ErrorCodePreParamsGeneration       ErrorCode = "ERROR_PRE_PARAMS_GENERATION"
	ErrorCodeTSSPartyCreation          ErrorCode = "ERROR_TSS_PARTY_CREATION"

	// Data serialization errors
	ErrorCodeMarshalFailure   ErrorCode = "ERROR_MARSHAL_FAILURE"
	ErrorCodeUnmarshalFailure ErrorCode = "ERROR_UNMARSHAL_FAILURE"
	ErrorCodeDataCorruption   ErrorCode = "ERROR_DATA_CORRUPTION"

	// Storage errors
	ErrorCodeStorageRead  ErrorCode = "ERROR_STORAGE_READ"
	ErrorCodeStorageWrite ErrorCode = "ERROR_STORAGE_WRITE"
	ErrorCodeStorageInit  ErrorCode = "ERROR_STORAGE_INIT"

	// Message and verification errors
	ErrorCodeMessageVerification ErrorCode = "ERROR_MESSAGE_VERIFICATION"
	ErrorCodeMessageFormat       ErrorCode = "ERROR_MESSAGE_FORMAT"
	ErrorCodeMessageDelivery     ErrorCode = "ERROR_MESSAGE_DELIVERY"
	ErrorCodeMaxDeliveryAttempts ErrorCode = "ERROR_MAX_DELIVERY_ATTEMPTS"

	// Configuration errors
	ErrorCodeInvalidConfiguration ErrorCode = "ERROR_INVALID_CONFIGURATION"
	ErrorCodeInvalidThreshold     ErrorCode = "ERROR_INVALID_THRESHOLD"
	ErrorCodeInvalidSessionType   ErrorCode = "ERROR_INVALID_SESSION_TYPE"

	// Resource errors
	ErrorCodeResourceExhausted ErrorCode = "ERROR_RESOURCE_EXHAUSTED"
	ErrorCodeMemoryAllocation  ErrorCode = "ERROR_MEMORY_ALLOCATION"
	ErrorCodeConcurrencyLimit  ErrorCode = "ERROR_CONCURRENCY_LIMIT"

	// Operation-specific errors
	ErrorCodeKeygenFailure  ErrorCode = "ERROR_KEYGEN_FAILURE"
	ErrorCodeSigningFailure ErrorCode = "ERROR_SIGNING_FAILURE"
	ErrorCodeReshareFailure ErrorCode = "ERROR_RESHARE_FAILURE"

	// Context and cancellation errors
	ErrorCodeContextCancelled ErrorCode = "ERROR_CONTEXT_CANCELLED"
	ErrorCodeOperationAborted ErrorCode = "ERROR_OPERATION_ABORTED"
	ErrorCodeNotMajority      ErrorCode = "ERROR_NOT_MAJORITY"
	ErrorCodeClusterNotReady  ErrorCode = "ERROR_CLUSTER_NOT_READY"
)

// GetErrorCodeFromError attempts to categorize a generic error into a specific error code
func GetErrorCodeFromError(err error) ErrorCode {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Check for specific error patterns
	switch {
	case contains(errStr, "validation"):
		return ErrorCodeMsgValidation
	case contains(errStr, "timeout", "timed out"):
		return ErrorCodeNetworkTimeout
	case contains(errStr, "connection", "connect"):
		return ErrorCodeNetworkConnection
	case contains(errStr, "send"):
		return ErrorCodePeerUnavailable
	case contains(errStr, "not enough", "insufficient"):
		return ErrorCodeInsufficientParticipants
	case contains(errStr, "incompatible"):
		return ErrorCodeIncompatiblePeerIDs
	case contains(errStr, "not found", "no such key"):
		return ErrorCodeKeyNotFound
	case contains(errStr, "exists"):
		return ErrorCodeKeyAlreadyExists
	case contains(errStr, "marshal"):
		return ErrorCodeMarshalFailure
	case contains(errStr, "unmarshal"):
		return ErrorCodeUnmarshalFailure
	case contains(errStr, "storage", "kvstore"):
		return ErrorCodeStorageRead
	case contains(errStr, "save", "put"):
		return ErrorCodeStorageWrite
	case contains(errStr, "session"):
		return ErrorCodeSessionCreation
	case contains(errStr, "verify", "verification"):
		return ErrorCodeMessageVerification
	case contains(errStr, "delivery", "deliver"):
		return ErrorCodeMessageDelivery
	case contains(errStr, "context", "cancelled"):
		return ErrorCodeContextCancelled
	case contains(errStr, "invalid signature from initiator"):
		return ErrorCodeInvalidInitiatorSignature
	case contains(errStr, "duplicate"):
		return ErrorCodeSessionDuplicate
	default:
		return ErrorCodeUnknown
	}
}

// Helper function for case-insensitive string matching
func contains(str string, patterns ...string) bool {
	str = strings.ToLower(str)
	for _, pattern := range patterns {
		if strings.Contains(str, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}
