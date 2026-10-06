package cosigner

import (
	"testing"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
	sdkstorage "github.com/fystack/mpcium-sdk/storage"
)

func TestBadgerStoresKeepKeyCommitteePerProtocolAndKey(t *testing.T) {
	stores, err := newBadgerStores(t.TempDir(), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer stores.Close()

	missing, err := stores.LoadKeyCommittee(sdkprotocol.ProtocolTypeEdDSA, "wallet-1")
	if err != nil || missing != nil {
		t.Fatalf("LoadKeyCommittee() = %v, %v; want nil, nil before anything is pinned", missing, err)
	}

	committee := &sdkstorage.KeyCommittee{Threshold: 1, Participants: []*sdkprotocol.SessionParticipant{
		{ParticipantID: "node", PartyKey: []byte("node"), IdentityPublicKey: []byte("node-pub")},
		{ParticipantID: "phone", PartyKey: []byte("phone"), IdentityPublicKey: []byte("phone-pub"), Approver: true},
	}}
	if err := stores.SaveKeyCommittee(sdkprotocol.ProtocolTypeEdDSA, "wallet-1", committee); err != nil {
		t.Fatal(err)
	}

	loaded, err := stores.LoadKeyCommittee(sdkprotocol.ProtocolTypeEdDSA, "wallet-1")
	if err != nil || loaded == nil || loaded.Threshold != 1 || len(loaded.Participants) != 2 || !loaded.Participants[1].Approver {
		t.Fatalf("LoadKeyCommittee() = %+v, %v", loaded, err)
	}
	other, err := stores.LoadKeyCommittee(sdkprotocol.ProtocolTypeECDSA, "wallet-1")
	if err != nil || other != nil {
		t.Fatalf("committee leaked across protocols: %+v, %v", other, err)
	}
}
