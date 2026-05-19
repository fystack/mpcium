package cosigner

import "fmt"

const topicPrefix = "mpc.v1"

func controlSubject(participantID string) string {
	return fmt.Sprintf("%s.peer.%s.control", topicPrefix, participantID)
}

func p2pSubject(participantID, sessionID string) string {
	return fmt.Sprintf("%s.peer.%s.session.%s.p2p", topicPrefix, participantID, sessionID)
}

func p2pWildcardSubject(participantID string) string {
	return fmt.Sprintf("%s.peer.%s.session.*.p2p", topicPrefix, participantID)
}

func sessionEventSubject(sessionID string) string {
	return fmt.Sprintf("%s.session.%s.event", topicPrefix, sessionID)
}

func presenceSubject(participantID string) string {
	return fmt.Sprintf("%s.peer.%s.presence", topicPrefix, participantID)
}
