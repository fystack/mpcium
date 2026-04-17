package cosigner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
	sdkprotocol "github.com/vietddude/mpcium-sdk/protocol"
)

type NATSRelay struct {
	nc *nats.Conn
}

func NewNATSRelay(cfg natsConfig) (Relay, error) {
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
	}
	if cfg.Username != "" {
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}
	if cfg.TLS != nil {
		tlsCfg, err := buildNATSTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		opts = append(opts, nats.Secure(tlsCfg))
	}
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	return &NATSRelay{nc: nc}, nil
}

func buildNATSTLSConfig(cfg *tlsConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACert != "" {
		caPEM, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read nats ca cert: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caPEM); !ok {
			return nil, fmt.Errorf("parse nats ca cert")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		if cfg.ClientCert == "" || cfg.ClientKey == "" {
			return nil, fmt.Errorf("both nats tls client_cert and client_key are required")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load nats client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

func (t *NATSRelay) Subscribe(subject string, handler func([]byte)) (Subscription, error) {
	logger.Info("relay nats subscribe", "subject", subject)
	return t.nc.Subscribe(subject, func(msg *nats.Msg) {
		handler(msg.Data)
	})
}

func (t *NATSRelay) Publish(subject string, payload []byte) error {
	logger.Debug("relay nats publish", "subject", subject)
	return t.nc.Publish(subject, payload)
}

func (t *NATSRelay) Flush() error {
	return t.nc.Flush()
}

func (t *NATSRelay) Close() {
	t.nc.Close()
}

func (t *NATSRelay) ProtocolType() sdkprotocol.TransportType {
	return sdkprotocol.TransportTypeNATS
}
