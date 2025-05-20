package mpc

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/google/uuid"
)

const (
	PurposeKeygen    string = "keygen"
	PurposeSign      string = "sign"
	PurposeResharing string = "resharing"
)

type ID string

type Node struct {
	nodeID  string
	peerIDs []string

	pubSub         messaging.PubSub
	direct         messaging.DirectMessaging
	kvstore        kvstore.KVStore
	keyinfoStore   keyinfo.Store
	ecdsaPreParams *keygen.LocalPreParams
	identityStore  identity.Store

	peerRegistry PeerRegistry
}

func CreatePartyID(nodeID string, label string) *tss.PartyID {
	partyID := uuid.NewString()
	key := big.NewInt(0).SetBytes([]byte(nodeID + ":" + label))
	return tss.NewPartyID(partyID, label, key)
}

func PartyIDToNodeID(partyID *tss.PartyID) string {
	return string(partyID.KeyInt().Bytes())
}

func ComparePartyIDs(x, y *tss.PartyID) bool {
	return bytes.Equal(x.KeyInt().Bytes(), y.KeyInt().Bytes())
}

func ComposeReadyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func NewNode(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	peerRegistry PeerRegistry,
	identityStore identity.Store,
) *Node {
	preParams, err := keygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		logger.Fatal("Generate pre params failed", err)
	}
	logger.Info("Starting new node, preparams is generated successfully!")

	go peerRegistry.WatchPeersReady()

	return &Node{
		nodeID:         nodeID,
		peerIDs:        peerIDs,
		pubSub:         pubSub,
		direct:         direct,
		kvstore:        kvstore,
		keyinfoStore:   keyinfoStore,
		ecdsaPreParams: preParams,
		peerRegistry:   peerRegistry,
		identityStore:  identityStore,
	}
}

func (p *Node) ID() string {
	return p.nodeID
}

func (p *Node) CreateKeyGenSession(walletID string, threshold int, successQueue messaging.MessageQueue) (*KeygenSession, error) {
	if p.peerRegistry.GetReadyPeersCount() < int64(threshold+1) {
		return nil, fmt.Errorf("Not enough peers to create gen session! Expected %d, got %d", threshold+1, p.peerRegistry.GetReadyPeersCount())
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	session := NewKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.ecdsaPreParams,
		p.kvstore,
		p.keyinfoStore,
		successQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateEDDSAKeyGenSession(walletID string, threshold int, successQueue messaging.MessageQueue) (*EDDSAKeygenSession, error) {
	if p.peerRegistry.GetReadyPeersCount() < int64(threshold+1) {
		return nil, fmt.Errorf("Not enough peers to create gen session! Expected %d, got %d", threshold+1, p.peerRegistry.GetReadyPeersCount())
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	session := NewEDDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		successQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateSigningSession(
	walletID string,
	txID string,
	networkInternalCode string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (*SigningSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	keyInfo, err := p.keyinfoStore.Get(fmt.Sprintf("eddsa:%s", walletID))
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}
	var selfPartyID *tss.PartyID
	var allPartyIDs []*tss.PartyID
	if keyInfo.IsReshared {
		selfPartyID, allPartyIDs = p.generatePartyIDs(PurposeResharing, readyPeerIDs)
	} else {
		selfPartyID, allPartyIDs = p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	}
	session := NewSigningSession(
		walletID,
		txID,
		networkInternalCode,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.ecdsaPreParams,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateEDDSASigningSession(
	walletID string,
	txID string,
	networkInternalCode string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (*EDDSASigningSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	keyInfo, err := p.keyinfoStore.Get(fmt.Sprintf("eddsa:%s", walletID))
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}
	var selfPartyID *tss.PartyID
	var allPartyIDs []*tss.PartyID
	if keyInfo.IsReshared {
		selfPartyID, allPartyIDs = p.generatePartyIDs(PurposeResharing, readyPeerIDs)
	} else {
		selfPartyID, allPartyIDs = p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	}
	session := NewEDDSASigningSession(
		walletID,
		txID,
		networkInternalCode,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateECDSAResharingSession(walletID string, isOldParticipant bool, readyPeerIDs []string, newThreshold int, resultQueue messaging.MessageQueue) (*ECDSAResharingSession, error) {
	// Get existing key info to determine old participants
	keyInfo, err := p.keyinfoStore.Get(fmt.Sprintf("ecdsa:%s", walletID))
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}

	oldSelfPartyID, oldPartyIDs := p.generatePartyIDs(PurposeKeygen, keyInfo.ParticipantPeerIDs)
	newSelfPartyID, newPartyIDs := p.generatePartyIDs(PurposeResharing, readyPeerIDs)

	var selfPartyID *tss.PartyID
	if isOldParticipant {
		selfPartyID = oldSelfPartyID
	} else {
		selfPartyID = newSelfPartyID
	}

	session := ECDSANewResharingSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		oldPartyIDs,
		newPartyIDs,
		keyInfo.Threshold,
		newThreshold,
		p.ecdsaPreParams,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
		isOldParticipant,
	)
	return session, nil
}

func (p *Node) CreeateEDDSAResharingSession(walletID string, isOldParticipant bool, readyPeerIDs []string, newThreshold int, resultQueue messaging.MessageQueue) (*EDDSAResharingSession, error) {
	keyInfo, err := p.keyinfoStore.Get(fmt.Sprintf("eddsa:%s", walletID))
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}

	oldSelfPartyID, oldPartyIDs := p.generatePartyIDs(PurposeKeygen, keyInfo.ParticipantPeerIDs)
	newSelfPartyID, newPartyIDs := p.generatePartyIDs(PurposeResharing, readyPeerIDs)

	var selfPartyID *tss.PartyID
	if isOldParticipant {
		selfPartyID = oldSelfPartyID
	} else {
		selfPartyID = newSelfPartyID
	}

	session := EDDSANewResharingSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		oldPartyIDs,
		newPartyIDs,
		keyInfo.Threshold,
		newThreshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
		isOldParticipant,
	)
	return session, nil
}

func (p *Node) generatePartyIDs(purpose string, readyPeerIDs []string) (self *tss.PartyID, all []*tss.PartyID) {
	var selfPartyID *tss.PartyID
	partyIDs := make([]*tss.PartyID, len(readyPeerIDs))
	for i, peerID := range readyPeerIDs {
		if peerID == p.nodeID {
			selfPartyID = CreatePartyID(peerID, purpose)
			partyIDs[i] = selfPartyID
		} else {
			partyIDs[i] = CreatePartyID(peerID, purpose)
		}
	}
	allPartyIDs := tss.SortPartyIDs(partyIDs, 0)
	return selfPartyID, allPartyIDs
}

func (p *Node) Close() {
	err := p.peerRegistry.Resign()
	if err != nil {
		logger.Error("Resign failed", err)
	}
}

func (p *Node) GetKeyInfo(key string) (*keyinfo.KeyInfo, error) {
	return p.keyinfoStore.Get(key)
}

func (p *Node) GetReadyPeersIncludeSelf() []string {
	return p.peerRegistry.GetReadyPeersIncludeSelf()
}

func (p *Node) GetKVStore() kvstore.KVStore {
	return p.kvstore
}
