package cosigner

import (
	"fmt"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium/pkg/logger"
)

const mqttOperationTimeout = 10 * time.Second

type mqttRelay struct {
	client mqtt.Client
}

func NewMQTTRelay(cfg mqttConfig) (Relay, error) {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(cfg.Broker)
	opts.SetClientID(cfg.ClientID)
	opts.SetUsername(cfg.Username)
	opts.SetPassword(cfg.Password)
	opts.SetCleanSession(true)
	opts.SetAutoReconnect(true)
	opts.SetOrderMatters(false)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	if !token.WaitTimeout(mqttOperationTimeout) {
		return nil, fmt.Errorf("connect mqtt timeout")
	}
	if err := token.Error(); err != nil {
		return nil, fmt.Errorf("connect mqtt: %w", err)
	}
	return &mqttRelay{client: client}, nil
}

func (r *mqttRelay) Subscribe(subject string, handler func([]byte)) (Subscription, error) {
	topic := natsToMQTTTopic(subject)
	logger.Info("relay mqtt subscribe", "subject", subject, "topic", topic)
	token := r.client.Subscribe(topic, 1, func(_ mqtt.Client, msg mqtt.Message) {
		logger.Debug("relay mqtt received message", "topic", msg.Topic(), "bytes", len(msg.Payload()))
		handler(append([]byte(nil), msg.Payload()...))
	})
	if !token.WaitTimeout(mqttOperationTimeout) {
		return nil, fmt.Errorf("subscribe mqtt timeout topic=%s", topic)
	}
	if err := token.Error(); err != nil {
		return nil, fmt.Errorf("subscribe mqtt topic=%s: %w", topic, err)
	}
	return mqttSubscription{client: r.client, topic: topic}, nil
}

func (r *mqttRelay) Publish(subject string, payload []byte) error {
	topic := natsToMQTTTopic(subject)
	logger.Debug("relay mqtt publish", "subject", subject, "topic", topic)
	token := r.client.Publish(topic, 1, false, payload)
	if !token.WaitTimeout(mqttOperationTimeout) {
		return fmt.Errorf("publish mqtt timeout topic=%s", topic)
	}
	if err := token.Error(); err != nil {
		return fmt.Errorf("publish mqtt topic=%s: %w", topic, err)
	}
	return nil
}

func (r *mqttRelay) Flush() error {
	return nil
}

func (r *mqttRelay) Close() {
	r.client.Disconnect(250)
}

func (r *mqttRelay) ProtocolType() sdkprotocol.TransportType {
	return sdkprotocol.TransportTypeMQTT
}

type mqttSubscription struct {
	client mqtt.Client
	topic  string
}

func (s mqttSubscription) Unsubscribe() error {
	if s.client == nil || s.topic == "" {
		return nil
	}
	unsub := s.client.Unsubscribe(s.topic)
	if !unsub.WaitTimeout(mqttOperationTimeout) {
		return fmt.Errorf("unsubscribe mqtt timeout")
	}
	return unsub.Error()
}

func natsToMQTTTopic(subject string) string {
	replacer := strings.NewReplacer(".", "/", "*", "+")
	return replacer.Replace(subject)
}
