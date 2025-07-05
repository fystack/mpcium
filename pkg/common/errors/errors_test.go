package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWrap(t *testing.T) {
	originalErr := errors.New("original error")
	wrappingMessage := "additional context"
	
	wrappedErr := Wrap(originalErr, wrappingMessage)
	
	assert.Error(t, wrappedErr)
	assert.Contains(t, wrappedErr.Error(), wrappingMessage)
	assert.Contains(t, wrappedErr.Error(), "original error")
	assert.True(t, errors.Is(wrappedErr, originalErr))
}

func TestWrap_NilError(t *testing.T) {
	wrappingMessage := "additional context"
	
	wrappedErr := Wrap(nil, wrappingMessage)
	
	assert.Error(t, wrappedErr)
	assert.Contains(t, wrappedErr.Error(), wrappingMessage)
	assert.Contains(t, wrappedErr.Error(), "<nil>")
}

func TestNew(t *testing.T) {
	message := "test error message"
	
	err := New(message)
	
	assert.Error(t, err)
	assert.Equal(t, message, err.Error())
}

func TestNew_EmptyMessage(t *testing.T) {
	err := New("")
	
	assert.Error(t, err)
	assert.Equal(t, "", err.Error())
}

func TestWrap_ChainedErrors(t *testing.T) {
	baseErr := errors.New("base error")
	firstWrap := Wrap(baseErr, "first wrap")
	secondWrap := Wrap(firstWrap, "second wrap")
	
	assert.Error(t, secondWrap)
	assert.Contains(t, secondWrap.Error(), "second wrap")
	assert.Contains(t, secondWrap.Error(), "first wrap")
	assert.Contains(t, secondWrap.Error(), "base error")
	assert.True(t, errors.Is(secondWrap, baseErr))
	assert.True(t, errors.Is(secondWrap, firstWrap))
}

func TestWrap_ErrorFormatting(t *testing.T) {
	originalErr := errors.New("database connection failed")
	context := "failed to initialize user repository"
	
	wrappedErr := Wrap(originalErr, context)
	expectedMessage := "failed to initialize user repository: database connection failed"
	
	assert.Equal(t, expectedMessage, wrappedErr.Error())
}