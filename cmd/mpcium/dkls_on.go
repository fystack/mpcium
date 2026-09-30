//go:build dkls

package main

import (
	"github.com/fystack/mpcium/pkg/eventconsumer"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/mpc/dkls"
	"github.com/spf13/viper"
)

// Must start before the node is marked ready, so its router is subscribed when peers send.
func startDkls(
	nodeID string,
	pubsub messaging.PubSub,
	identityStore identity.Store,
	kv kvstore.KVStore,
	keyInfo keyinfo.Store,
	peers mpc.PeerRegistry,
	genKeyResultQueue messaging.MessageQueue,
	signingResultQueue messaging.MessageQueue,
) (stop func()) {
	service, err := dkls.NewService(dkls.Config{
		NodeID:   nodeID,
		PubSub:   pubsub,
		Identity: identityStore,
		KV:       kv,
		KeyInfo:  keyInfo,
		Peers:    peers,
	})
	if err != nil {
		logger.Fatal("Failed to start dkls service", err)
	}
	consumer := eventconsumer.NewDklsConsumer(service, pubsub, identityStore, genKeyResultQueue, signingResultQueue, viper.GetInt("mpc_threshold"))
	consumer.Run()
	return func() {
		_ = consumer.Close()
		service.Close()
	}
}
