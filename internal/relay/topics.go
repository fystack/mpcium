package relay

import (
	"fmt"
	"strings"
)

const (
	natsControlSuffix = ".peer.*.control"
	natsP2PSuffix     = ".peer.*.session.*.p2p"

	mqttP2PFilterSuffix      = "/peer/+/session/+/p2p"
	mqttEventFilterSuffix    = "/session/+/event"
	mqttPresenceFilterSuffix = "/peer/+/presence"
)

type topicMapper struct {
	natsPrefix string
	mqttPrefix string
}

func newTopicMapper(natsPrefix, mqttPrefix string) topicMapper {
	return topicMapper{
		natsPrefix: strings.Trim(natsPrefix, "."),
		mqttPrefix: strings.Trim(mqttPrefix, "/"),
	}
}

func (m topicMapper) natsToMQTT(subject string) (string, bool) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", false
	}
	if !strings.HasPrefix(subject, m.natsPrefix+".") {
		return "", false
	}
	if !m.allowNATSBridgeSubject(subject) {
		return "", false
	}
	trimmed := strings.TrimPrefix(subject, m.natsPrefix+".")
	return m.mqttPrefix + "/" + strings.ReplaceAll(trimmed, ".", "/"), true
}

func (m topicMapper) mqttToNATS(topic string) (string, bool) {
	topic = strings.Trim(strings.TrimSpace(topic), "/")
	if topic == "" {
		return "", false
	}
	if !strings.HasPrefix(topic, m.mqttPrefix+"/") {
		return "", false
	}
	if !m.allowMQTTBridgeTopic(topic) {
		return "", false
	}
	trimmed := strings.TrimPrefix(topic, m.mqttPrefix+"/")
	return m.natsPrefix + "." + strings.ReplaceAll(trimmed, "/", "."), true
}

func (m topicMapper) natsControlFilter() string {
	return m.natsPrefix + natsControlSuffix
}

func (m topicMapper) natsP2PFilter() string {
	return m.natsPrefix + natsP2PSuffix
}

func (m topicMapper) mqttP2PFilter() string {
	return m.mqttPrefix + mqttP2PFilterSuffix
}

func (m topicMapper) mqttSessionEventFilter() string {
	return m.mqttPrefix + mqttEventFilterSuffix
}

func (m topicMapper) mqttPresenceFilter() string {
	return m.mqttPrefix + mqttPresenceFilterSuffix
}

func (m topicMapper) natsPresenceSubject(peerID string) string {
	return fmt.Sprintf("%s.peer.%s.presence", m.natsPrefix, peerID)
}

func (m topicMapper) allowNATSBridgeSubject(subject string) bool {
	parts := strings.Split(subject, ".")
	prefix := strings.Split(m.natsPrefix, ".")
	if len(parts) < len(prefix)+3 {
		return false
	}
	for i := range prefix {
		if parts[i] != prefix[i] {
			return false
		}
	}
	rel := parts[len(prefix):]
	if len(rel) == 3 && rel[0] == "peer" && rel[2] == "control" {
		return rel[1] != ""
	}
	if len(rel) == 5 && rel[0] == "peer" && rel[2] == "session" && rel[4] == "p2p" {
		return rel[1] != "" && rel[3] != ""
	}
	return false
}

func (m topicMapper) allowMQTTBridgeTopic(topic string) bool {
	parts := strings.Split(strings.Trim(topic, "/"), "/")
	prefix := strings.Split(m.mqttPrefix, "/")
	if len(parts) < len(prefix)+3 {
		return false
	}
	for i := range prefix {
		if parts[i] != prefix[i] {
			return false
		}
	}
	rel := parts[len(prefix):]
	if len(rel) == 5 && rel[0] == "peer" && rel[2] == "session" && rel[4] == "p2p" {
		return rel[1] != "" && rel[3] != ""
	}
	if len(rel) == 3 && rel[0] == "peer" && rel[2] == "presence" {
		return rel[1] != ""
	}
	if len(rel) == 3 && rel[0] == "session" && rel[2] == "event" {
		return rel[1] != ""
	}
	return false
}

func (m topicMapper) allowMQTTRead(clientID, topic string) bool {
	parts := strings.Split(strings.Trim(topic, "/"), "/")
	prefix := strings.Split(m.mqttPrefix, "/")
	if len(parts) < len(prefix)+3 {
		return false
	}
	for i := range prefix {
		if parts[i] != prefix[i] {
			return false
		}
	}
	rel := parts[len(prefix):]
	if len(rel) == 3 && rel[0] == "peer" && rel[2] == "control" {
		return rel[1] == clientID
	}
	if len(rel) == 5 && rel[0] == "peer" && rel[2] == "session" && rel[4] == "p2p" {
		return rel[1] == clientID
	}
	return false
}

func (m topicMapper) allowMQTTWrite(topic string) bool {
	return m.allowMQTTBridgeTopic(topic)
}
