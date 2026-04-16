package coordinator

import (
	"errors"
	"fmt"
)

const (
	ErrorCodeInvalidJSON        = "INVALID_JSON"
	ErrorCodeValidation         = "VALIDATION_ERROR"
	ErrorCodeUnauthorized       = "UNAUTHORIZED"
	ErrorCodeConflict           = "CONFLICT"
	ErrorCodeUnavailable        = "UNAVAILABLE"
	ErrorCodeInternal           = "INTERNAL_ERROR"
	ErrorCodeTimeout            = "SESSION_TIMEOUT"
	ErrorCodeParticipantFailed  = "PARTICIPANT_FAILED"
	ErrorCodeResultHashMismatch = "RESULT_HASH_MISMATCH"
	ErrorCodeInvalidTransition  = "INVALID_TRANSITION"
	ErrorCodeUnsupported        = "UNSUPPORTED_OPERATION"
)

type CoordinatorError struct {
	Code    string
	Message string
}

func (e *CoordinatorError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func newCoordinatorError(code, message string) *CoordinatorError {
	return &CoordinatorError{Code: code, Message: message}
}

func AsCoordinatorError(err error, target **CoordinatorError) bool {
	return errors.As(err, target)
}
