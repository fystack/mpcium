package event

import "testing"

func TestResultStreamSubjects(t *testing.T) {
	subjects := ResultStreamSubjects()
	expected := []string{
		"mpc.mpc_keygen_result.>",
		"mpc.mpc_signing_result.>",
		"mpc.mpc_reshare_result.>",
	}

	if len(subjects) != len(expected) {
		t.Fatalf("unexpected subject count: got %d want %d", len(subjects), len(expected))
	}

	for i := range expected {
		if subjects[i] != expected[i] {
			t.Fatalf("unexpected subject at index %d: got %q want %q", i, subjects[i], expected[i])
		}
	}
}

func TestScopedResultSubjects(t *testing.T) {
	tests := []struct {
		name                      string
		clientID                  string
		keygenResult              string
		keygenSubscription        string
		signingResult             string
		reshareResult             string
		reshareSubscription       string
		keygenConsumerName        string
		scopedOperationIdentifier string
	}{
		{
			name:                      "legacy",
			clientID:                  "",
			keygenResult:              "mpc.mpc_keygen_result.wallet-1",
			keygenSubscription:        "mpc.mpc_keygen_result.*",
			signingResult:             "mpc.mpc_signing_result.complete",
			reshareResult:             "mpc.mpc_reshare_result.session-1",
			reshareSubscription:       "mpc.mpc_reshare_result.*",
			keygenConsumerName:        "mpc_keygen_result",
			scopedOperationIdentifier: "wallet-1",
		},
		{
			name:                      "scoped",
			clientID:                  "svc-a",
			keygenResult:              "mpc.mpc_keygen_result.svc-a.wallet-1",
			keygenSubscription:        "mpc.mpc_keygen_result.svc-a.*",
			signingResult:             "mpc.mpc_signing_result.svc-a.complete",
			reshareResult:             "mpc.mpc_reshare_result.svc-a.session-1",
			reshareSubscription:       "mpc.mpc_reshare_result.svc-a.*",
			keygenConsumerName:        "mpc_keygen_result.svc-a",
			scopedOperationIdentifier: "svc-a:wallet-1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := KeygenResultSubject(tc.clientID, "wallet-1"); got != tc.keygenResult {
				t.Fatalf("unexpected keygen result subject: got %q want %q", got, tc.keygenResult)
			}
			if got := KeygenResultSubscriptionSubject(tc.clientID); got != tc.keygenSubscription {
				t.Fatalf("unexpected keygen subscription subject: got %q want %q", got, tc.keygenSubscription)
			}
			if got := SigningResultSubject(tc.clientID); got != tc.signingResult {
				t.Fatalf("unexpected signing result subject: got %q want %q", got, tc.signingResult)
			}
			if got := ReshareResultSubject(tc.clientID, "session-1"); got != tc.reshareResult {
				t.Fatalf("unexpected reshare result subject: got %q want %q", got, tc.reshareResult)
			}
			if got := ReshareResultSubscriptionSubject(tc.clientID); got != tc.reshareSubscription {
				t.Fatalf("unexpected reshare subscription subject: got %q want %q", got, tc.reshareSubscription)
			}
			if got := ResultConsumerName("mpc_keygen_result", tc.clientID); got != tc.keygenConsumerName {
				t.Fatalf("unexpected consumer name: got %q want %q", got, tc.keygenConsumerName)
			}
			if got := ScopedOperationID(tc.clientID, "wallet-1"); got != tc.scopedOperationIdentifier {
				t.Fatalf("unexpected scoped operation id: got %q want %q", got, tc.scopedOperationIdentifier)
			}
		})
	}
}
