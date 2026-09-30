//go:build dkls

package dkls

import (
	"fmt"
	"sync"

	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
)

type Act string

const (
	ActKeygen Act = "keygen"
	ActSign   Act = "sign"
)

type Transport interface {
	Send(to string, msg types.DklsMessage) error
	Inbox() <-chan types.DklsMessage
	Close() error
}

type MessageAuthenticator interface {
	SignDklsMessage(msg *types.DklsMessage) ([]byte, error)
	VerifyDklsMessage(msg *types.DklsMessage) error
}

type NATSTransport struct {
	act        Act
	sessionKey string
	route      string
	router     *Router
	pubsub     messaging.PubSub
	auth       MessageAuthenticator
	inbox      chan types.DklsMessage
	closeOnce  sync.Once
}

// sessionKey is the walletID for keygen and walletID:txID for signing, since signs run concurrently.
func NewNATSTransport(sessionKey string, act Act, router *Router, pubsub messaging.PubSub, auth MessageAuthenticator) *NATSTransport {
	route := routeKey(act, sessionKey)
	return &NATSTransport{
		act:        act,
		sessionKey: sessionKey,
		route:      route,
		router:     router,
		pubsub:     pubsub,
		auth:       auth,
		inbox:      router.register(route),
	}
}

func (t *NATSTransport) Send(to string, msg types.DklsMessage) error {
	msg.Route = t.route
	msg.To = to
	sig, err := t.auth.SignDklsMessage(&msg)
	if err != nil {
		return fmt.Errorf("sign dkls message: %w", err)
	}
	msg.Signature = sig
	return t.pubsub.Publish(sessionSubject(to, t.act, t.sessionKey), msg.MarshalWire(), nil)
}

func (t *NATSTransport) Inbox() <-chan types.DklsMessage { return t.inbox }

func (t *NATSTransport) Close() error {
	t.closeOnce.Do(func() { t.router.unregister(t.route, t.inbox) })
	return nil
}
