package event

import "strings"

const ClientIDHeader = "ClientID"

const (
	keygenResultSubjectPrefix  = "mpc.mpc_keygen_result"
	signingResultSubjectPrefix = "mpc.mpc_signing_result"
	reshareResultSubjectPrefix = "mpc.mpc_reshare_result"
	signingResultCompleteToken = "complete"
)

func ResultStreamSubjects() []string {
	return []string{
		keygenResultSubjectPrefix + ".>",
		signingResultSubjectPrefix + ".>",
		reshareResultSubjectPrefix + ".>",
	}
}

func KeygenResultSubject(clientID, walletID string) string {
	return scopedSubject(keygenResultSubjectPrefix, clientID, walletID)
}

func KeygenResultSubscriptionSubject(clientID string) string {
	return scopedSubject(keygenResultSubjectPrefix, clientID, "*")
}

func SigningResultSubject(clientID string) string {
	return scopedSubject(signingResultSubjectPrefix, clientID, signingResultCompleteToken)
}

func SigningResultSubscriptionSubject(clientID string) string {
	return SigningResultSubject(clientID)
}

func ReshareResultSubject(clientID, sessionID string) string {
	return scopedSubject(reshareResultSubjectPrefix, clientID, sessionID)
}

func ReshareResultSubscriptionSubject(clientID string) string {
	return scopedSubject(reshareResultSubjectPrefix, clientID, "*")
}

func ResultConsumerName(base, clientID string) string {
	if clientID == "" {
		return base
	}
	return base + "." + clientID
}

func ScopedOperationID(clientID, operationID string) string {
	if clientID == "" {
		return operationID
	}
	return clientID + ":" + operationID
}

func scopedSubject(prefix, clientID, tail string) string {
	parts := []string{prefix}
	if clientID != "" {
		parts = append(parts, clientID)
	}
	parts = append(parts, tail)
	return strings.Join(parts, ".")
}
