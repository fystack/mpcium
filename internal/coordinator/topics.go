package coordinator

import "fmt"

const TopicPrefix = "mpc.v1"

func RequestSubject(op Operation) string {
	return fmt.Sprintf("%s.request.%s", TopicPrefix, op)
}

func PeerControlSubject(peerID string) string {
	return fmt.Sprintf("%s.peer.%s.control", TopicPrefix, peerID)
}

func PeerPresenceSubject(peerID string) string {
	return fmt.Sprintf("%s.peer.%s.presence", TopicPrefix, peerID)
}

func SessionEventSubject(sessionID string) string {
	return fmt.Sprintf("%s.session.%s.event", TopicPrefix, sessionID)
}

func SessionResultSubject(sessionID string) string {
	return fmt.Sprintf("%s.session.%s.result", TopicPrefix, sessionID)
}

func AllPresenceSubject() string {
	return fmt.Sprintf("%s.peer.*.presence", TopicPrefix)
}

func AllSessionEventsSubject() string {
	return fmt.Sprintf("%s.session.*.event", TopicPrefix)
}
