package cosigner

import "fmt"

const topicPrefix = "mpc.v1"

func controlSubject(peerID string) string {
	return fmt.Sprintf("%s.peer.%s.control", topicPrefix, peerID)
}

func p2pSubject(peerID, sessionID string) string {
	return fmt.Sprintf("%s.peer.%s.session.%s.p2p", topicPrefix, peerID, sessionID)
}

func p2pWildcardSubject(peerID string) string {
	return fmt.Sprintf("%s.peer.%s.session.*.p2p", topicPrefix, peerID)
}

func sessionEventSubject(sessionID string) string {
	return fmt.Sprintf("%s.session.%s.event", topicPrefix, sessionID)
}

func presenceSubject(peerID string) string {
	return fmt.Sprintf("%s.peer.%s.presence", topicPrefix, peerID)
}
