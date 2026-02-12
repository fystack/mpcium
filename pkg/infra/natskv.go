package infra

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// NatsKV defines the interface for Key-Value store operations using NATS JetStream
type NatsKV interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
	Delete(key string) error
	Keys(prefix string) ([]string, error)
	List(prefix string) (map[string][]byte, error)
}

// NatsKVStore implements NatsKV using NATS JetStream KeyValue
type NatsKVStore struct {
	kv jetstream.KeyValue
}

// NewNatsKVStore creates a new NatsKVStore.
// It attempts to create the bucket if it doesn't exist.
func NewNatsKVStore(js jetstream.JetStream, bucketName string) (*NatsKVStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  bucketName,
		Storage: jetstream.FileStorage,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create or bind to key value bucket %s: %w", bucketName, err)
	}

	return &NatsKVStore{kv: kv}, nil
}

// Put saves a key-value pair
func (s *NatsKVStore) Put(key string, value []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.kv.Put(ctx, key, value)
	if err != nil {
		return fmt.Errorf("failed to put key %s: %w", key, err)
	}
	return nil
}

// Get retrieves a value by key
func (s *NatsKVStore) Get(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entry, err := s.kv.Get(ctx, key)
	if err != nil {
		if err == jetstream.ErrKeyNotFound {
			return nil, nil // Return nil for not found, similar to Consul behavior when checking
		}
		return nil, fmt.Errorf("failed to get key %s: %w", key, err)
	}
	return entry.Value(), nil
}

// Delete removes a key
func (s *NatsKVStore) Delete(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.kv.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to delete key %s: %w", key, err)
	}
	return nil
}

// Keys returns all keys matching the prefix
func (s *NatsKVStore) Keys(prefix string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lister, err := s.kv.ListKeys(ctx)
	if err != nil {
		if err == jetstream.ErrNoKeysFound {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer func() {
		_ = lister.Stop()
	}()

	var matchedKeys []string
	for k := range lister.Keys() {
		if strings.HasPrefix(k, prefix) || prefix == "" {
			matchedKeys = append(matchedKeys, k)
		}
	}
	return matchedKeys, nil
}

// List returns a map of key-value pairs matching the prefix
func (s *NatsKVStore) List(prefix string) (map[string][]byte, error) {
	keys, err := s.Keys(prefix)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte)
	for _, k := range keys {
		val, err := s.Get(k)
		if err != nil {
			// If key was deleted in between, just skip
			continue
		}
		if val != nil {
			result[k] = val
		}
	}
	return result, nil
}
