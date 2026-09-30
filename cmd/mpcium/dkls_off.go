//go:build !dkls

package main

import (
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
)

func startDkls(
	string,
	messaging.PubSub,
	identity.Store,
	kvstore.KVStore,
	keyinfo.Store,
	mpc.PeerRegistry,
	messaging.MessageQueue,
	messaging.MessageQueue,
) (stop func()) {
	return func() {}
}
