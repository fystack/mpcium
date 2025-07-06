package messaging

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var (
	ErrInvalidStreamName    = errors.New("stream name cannot be empty")
	ErrInvalidSubjects      = errors.New("subjects cannot be empty")
	ErrConsumerCreation     = errors.New("failed to create consumer")
	ErrStreamCreation       = errors.New("failed to create stream")
	ErrInvalidConfiguration = errors.New("invalid configuration")
	ErrConnectionClosed     = errors.New("connection is closed")
	ErrSubscriptionClosed   = errors.New("subscription is closed")
)

const (
	DefaultAckWait             = 30 * time.Second
	DefaultMaxDeliveryAttempts = 3
	DefaultConsumerPrefix      = "consumer"
	DefaultStreamMaxAge        = 3 * time.Minute
	DefaultBackoffDuration     = 30 * time.Second
)

type MessageBroker interface {
	PublishMessage(ctx context.Context, subject string, data []byte) error
	CreateSubscription(ctx context.Context, consumerName, subject string, handler func(msg jetstream.Msg)) (MessageSubscription, error)
	GetStreamInfo(ctx context.Context) (*jetstream.StreamInfo, error)
	FetchMessages(ctx context.Context, consumerName, subject string, batchSize int, handler func(msg jetstream.Msg)) error
	Close() error
}

type MessageSubscription interface {
	Unsubscribe() error
}

type BrokerOption func(*brokerConfiguration)

type brokerConfiguration struct {
	streamName          string
	subjects            []string
	description         string
	retention           nats.RetentionPolicy
	storage             nats.StorageType
	maxAge              time.Duration
	discard             nats.DiscardPolicy
	ackWait             time.Duration
	maxDeliveryAttempts int
	consumerNamePrefix  string
	deliverPolicy       jetstream.DeliverPolicy
	backoffDurations    []time.Duration
}

func WithStreamDescription(description string) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.description = description
	}
}

func WithRetentionPolicy(policy nats.RetentionPolicy) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.retention = policy
	}
}

func WithStorageType(storage nats.StorageType) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.storage = storage
	}
}

func WithMaxAge(maxAge time.Duration) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.maxAge = maxAge
	}
}

func WithDiscardPolicy(policy nats.DiscardPolicy) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.discard = policy
	}
}

func WithAckWait(ackWait time.Duration) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.ackWait = ackWait
	}
}

func WithMaxDeliveryAttempts(maxAttempts int) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.maxDeliveryAttempts = maxAttempts
	}
}

func WithConsumerNamePrefix(prefix string) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.consumerNamePrefix = prefix
	}
}

func WithDeliverPolicy(policy jetstream.DeliverPolicy) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.deliverPolicy = policy
	}
}

func WithBackoffDurations(durations []time.Duration) BrokerOption {
	return func(cfg *brokerConfiguration) {
		cfg.backoffDurations = durations
	}
}

type jetStreamBroker struct {
	config brokerConfiguration
	js     jetstream.JetStream
	conn   *nats.Conn
}

func NewJetStreamBroker(
	ctx context.Context,
	natsConn *nats.Conn,
	streamName string,
	subjects []string,
	opts ...BrokerOption,
) (MessageBroker, error) {

	config := brokerConfiguration{
		streamName:          streamName,
		subjects:            subjects,
		description:         fmt.Sprintf("Stream for %s", streamName),
		retention:           nats.InterestPolicy,
		storage:             nats.MemoryStorage,
		maxAge:              DefaultStreamMaxAge,
		discard:             nats.DiscardOld,
		ackWait:             DefaultAckWait,
		maxDeliveryAttempts: DefaultMaxDeliveryAttempts,
		consumerNamePrefix:  DefaultConsumerPrefix,
		deliverPolicy:       jetstream.DeliverAllPolicy,
		backoffDurations:    []time.Duration{DefaultBackoffDuration, DefaultBackoffDuration, DefaultBackoffDuration},
	}

	for _, opt := range opts {
		opt(&config)
	}

	js, err := jetstream.New(natsConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	broker := &jetStreamBroker{
		config: config,
		js:     js,
		conn:   natsConn,
	}

	if err := broker.ensureStreamExists(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure stream exists: %w", err)
	}

	logger.Info("JetStream broker initialized successfully", "stream", streamName)
	return broker, nil
}

func (b *jetStreamBroker) ensureStreamExists(ctx context.Context) error {
	streamConfig := jetstream.StreamConfig{
		Name:        b.config.streamName,
		Description: b.config.description,
		Subjects:    b.config.subjects,
		MaxAge:      b.config.maxAge,
	}

	_, err := b.js.CreateOrUpdateStream(ctx, streamConfig)
	if err != nil {
		return fmt.Errorf("%w for stream '%s': %v", ErrStreamCreation, b.config.streamName, err)
	}

	return nil
}

func (b *jetStreamBroker) PublishMessage(ctx context.Context, subject string, data []byte) error {
	if b.conn.IsClosed() {
		return ErrConnectionClosed
	}

	_, err := b.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish message to subject %s: %w", subject, err)
	}

	return nil
}

func (b *jetStreamBroker) CreateSubscription(
	ctx context.Context,
	consumerName, subject string,
	handler func(msg jetstream.Msg),
) (MessageSubscription, error) {
	if b.conn.IsClosed() {
		return nil, ErrConnectionClosed
	}

	sanitizedName := sanitizeConsumerName(consumerName)
	logger.Info("Creating subscription", "consumer", sanitizedName, "subject", subject)

	consumerConfig := jetstream.ConsumerConfig{
		Name:          sanitizedName,
		Durable:       sanitizedName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    b.config.maxDeliveryAttempts + 1,
		BackOff:       b.config.backoffDurations,
		DeliverPolicy: b.config.deliverPolicy,
		FilterSubject: subject,
		AckWait:       b.config.ackWait,
	}

	consumer, err := b.js.CreateOrUpdateConsumer(ctx, b.config.streamName, consumerConfig)
	if err != nil {
		return nil, fmt.Errorf("%w for consumer '%s' on stream '%s': %v", ErrConsumerCreation, sanitizedName, b.config.streamName, err)
	}

	consumeContext, err := consumer.Consume(func(msg jetstream.Msg) {
		handler(msg)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start consuming messages for consumer '%s' on stream '%s': %w", sanitizedName, b.config.streamName, err)
	}

	subscription := &jetStreamSubscription{
		consumer:       consumer,
		consumeContext: consumeContext,
	}

	logger.Info("Subscription created successfully", "consumer", sanitizedName, "subject", subject)
	return subscription, nil
}

func (b *jetStreamBroker) GetStreamInfo(ctx context.Context) (*jetstream.StreamInfo, error) {
	stream, err := b.js.Stream(ctx, b.config.streamName)
	if err != nil {
		return nil, fmt.Errorf("failed to get stream '%s': %w", b.config.streamName, err)
	}

	return stream.Info(ctx)
}

func (b *jetStreamBroker) Close() error {
	if b.conn != nil && !b.conn.IsClosed() {
		b.conn.Close()
	}
	return nil
}

type jetStreamSubscription struct {
	consumer       jetstream.Consumer
	consumeContext jetstream.ConsumeContext
}

func (s *jetStreamSubscription) Unsubscribe() error {
	if s.consumeContext != nil {
		s.consumeContext.Stop()
	}
	return nil
}

func sanitizeConsumerName(name string) string {
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ">", "all")
	name = strings.ReplaceAll(name, "*", "any")

	if len(name) > 0 && !unicode.IsLetter(rune(name[0])) && name[0] != '_' {
		name = "_" + name
	}

	return name
}

func (b *jetStreamBroker) FetchMessages(
	ctx context.Context,
	consumerName, subject string,
	batchSize int,
	handler func(msg jetstream.Msg),
) error {
	if b.conn.IsClosed() {
		return ErrConnectionClosed
	}

	sanitizedName := sanitizeConsumerName(consumerName)
	logger.Info("Creating fetch-based subscription", "consumer", sanitizedName, "subject", subject)

	consumerConfig := jetstream.ConsumerConfig{
		Name:          sanitizedName,
		Durable:       sanitizedName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    b.config.maxDeliveryAttempts + 1,
		BackOff:       b.config.backoffDurations,
		DeliverPolicy: b.config.deliverPolicy,
		FilterSubject: subject,
		AckWait:       b.config.ackWait,
	}

	consumer, err := b.js.CreateOrUpdateConsumer(ctx, b.config.streamName, consumerConfig)
	if err != nil {
		return fmt.Errorf("%w for consumer '%s' on stream '%s': %v", ErrConsumerCreation, sanitizedName, b.config.streamName, err)
	}

	msgs, err := consumer.Fetch(batchSize, jetstream.FetchMaxWait(b.config.ackWait))
	if err != nil {
		return fmt.Errorf("failed to fetch messages for consumer '%s': %w", sanitizedName, err)
	}

	for msg := range msgs.Messages() {
		handler(msg)
	}

	logger.Info("Fetched messages successfully", "consumer", sanitizedName, "subject", subject, "count", len(msgs.Messages()))
	return nil
}
