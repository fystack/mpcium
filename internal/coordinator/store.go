package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sdkprotocol "github.com/fystack/mpcium-sdk/protocol"
)

type SnapshotStore interface {
	SaveSession(ctx context.Context, session *Session) error
	LoadSessions(ctx context.Context) ([]*Session, error)
	SaveKeyInfo(ctx context.Context, info KeyInfo) error
	LoadKeyInfos(ctx context.Context) ([]KeyInfo, error)
}

type AtomicFileSnapshotStore struct {
	dir string
}

func NewAtomicFileSnapshotStore(dir string) *AtomicFileSnapshotStore {
	return &AtomicFileSnapshotStore{dir: dir}
}

func (s *AtomicFileSnapshotStore) SaveSession(ctx context.Context, session *Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}
	path := filepath.Join(s.dir, "session_"+safeFilePart(session.ID)+".json")
	return writeJSONAtomic(path, session)
}

func (s *AtomicFileSnapshotStore) LoadSessions(ctx context.Context) ([]*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read snapshot dir: %w", err)
	}
	sessions := make([]*Session, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "session_") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read session snapshot %s: %w", entry.Name(), err)
		}
		var session Session
		if err := json.Unmarshal(raw, &session); err != nil {
			return nil, fmt.Errorf("parse session snapshot %s: %w", entry.Name(), err)
		}
		sessions = append(sessions, &session)
	}
	return sessions, nil
}

func (s *AtomicFileSnapshotStore) SaveKeyInfo(ctx context.Context, info KeyInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}
	path := filepath.Join(s.dir, "keyinfo_"+safeFilePart(info.WalletID)+".json")
	return writeJSONAtomic(path, info)
}

func (s *AtomicFileSnapshotStore) LoadKeyInfos(ctx context.Context) ([]KeyInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read snapshot dir: %w", err)
	}
	infos := make([]KeyInfo, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "keyinfo_") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read key info snapshot %s: %w", entry.Name(), err)
		}
		var info KeyInfo
		if err := json.Unmarshal(raw, &info); err != nil {
			return nil, fmt.Errorf("parse key info snapshot %s: %w", entry.Name(), err)
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func writeJSONAtomic(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write snapshot temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace snapshot: %w", err)
	}
	return nil
}

func safeFilePart(value string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_")
	return replacer.Replace(value)
}

type MemorySessionStore struct {
	mu        sync.RWMutex
	sessions  map[string]*Session
	requests  map[string]string
	snapshots SnapshotStore
}

func NewMemorySessionStore(ctx context.Context, snapshots SnapshotStore) (*MemorySessionStore, error) {
	store := &MemorySessionStore{
		sessions:  make(map[string]*Session),
		requests:  make(map[string]string),
		snapshots: snapshots,
	}
	if snapshots == nil {
		return store, nil
	}
	sessions, err := snapshots.LoadSessions(ctx)
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		cloned := cloneSession(session)
		store.sessions[cloned.ID] = cloned
		if cloned.RequestID != "" {
			store.requests[cloned.RequestID] = cloned.ID
		}
	}
	return store, nil
}

func (s *MemorySessionStore) Create(ctx context.Context, session *Session) error {
	s.mu.Lock()
	if _, ok := s.sessions[session.ID]; ok {
		s.mu.Unlock()
		return newCoordinatorError(ErrorCodeConflict, "session already exists")
	}
	if existingID, ok := s.requests[session.RequestID]; ok && existingID != "" {
		s.mu.Unlock()
		return newCoordinatorError(ErrorCodeConflict, "request already accepted")
	}
	s.sessions[session.ID] = cloneSession(session)
	s.requests[session.RequestID] = session.ID
	s.mu.Unlock()
	return s.snapshot(ctx, session)
}

func (s *MemorySessionStore) Save(ctx context.Context, session *Session) error {
	s.mu.Lock()
	if _, ok := s.sessions[session.ID]; !ok {
		s.mu.Unlock()
		return newCoordinatorError(ErrorCodeValidation, "unknown session")
	}
	s.sessions[session.ID] = cloneSession(session)
	s.mu.Unlock()
	return s.snapshot(ctx, session)
}

func (s *MemorySessionStore) Get(_ context.Context, sessionID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	return cloneSession(session), true
}

func (s *MemorySessionStore) GetByRequestID(_ context.Context, requestID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sessionID, ok := s.requests[requestID]
	if !ok {
		return nil, false
	}
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	return cloneSession(session), true
}

func (s *MemorySessionStore) ListActive(_ context.Context) []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		if !session.State.Terminal() {
			sessions = append(sessions, cloneSession(session))
		}
	}
	return sessions
}

func (s *MemorySessionStore) snapshot(ctx context.Context, session *Session) error {
	if s.snapshots == nil {
		return nil
	}
	return s.snapshots.SaveSession(ctx, session)
}

func cloneSession(session *Session) *Session {
	if session == nil {
		return nil
	}
	cloned := *session
	cloned.Start = cloneSessionStart(session.Start)
	cloned.Participants = cloneParticipants(session.Participants)
	cloned.ParticipantKeys = cloneKeyMap(session.ParticipantKeys)
	cloned.Result = cloneResult(session.Result)
	cloned.ParticipantState = make(map[string]*ParticipantState, len(session.ParticipantState))
	for peerID, state := range session.ParticipantState {
		stateCopy := *state
		cloned.ParticipantState[peerID] = &stateCopy
	}
	if session.CompletedAt != nil {
		completedAt := *session.CompletedAt
		cloned.CompletedAt = &completedAt
	}
	return &cloned
}

func cloneSessionStart(start *sdkprotocol.SessionStart) *sdkprotocol.SessionStart {
	if start == nil {
		return nil
	}
	cloned := *start
	cloned.Participants = cloneParticipants(start.Participants)
	if start.Keygen != nil {
		keygen := *start.Keygen
		cloned.Keygen = &keygen
	}
	if start.Sign != nil {
		sign := *start.Sign
		sign.SigningInput = append([]byte(nil), start.Sign.SigningInput...)
		if start.Sign.Derivation != nil {
			derivation := *start.Sign.Derivation
			derivation.Path = append([]uint32(nil), start.Sign.Derivation.Path...)
			derivation.Delta = append([]byte(nil), start.Sign.Derivation.Delta...)
			sign.Derivation = &derivation
		}
		cloned.Sign = &sign
	}
	if start.Reshare != nil {
		reshare := *start.Reshare
		reshare.NewParticipants = cloneParticipants(start.Reshare.NewParticipants)
		cloned.Reshare = &reshare
	}
	return &cloned
}

func cloneParticipants(participants []*sdkprotocol.SessionParticipant) []*sdkprotocol.SessionParticipant {
	out := make([]*sdkprotocol.SessionParticipant, 0, len(participants))
	for _, participant := range participants {
		if participant == nil {
			continue
		}
		cloned := *participant
		cloned.PartyKey = append([]byte(nil), participant.PartyKey...)
		cloned.IdentityPublicKey = append([]byte(nil), participant.IdentityPublicKey...)
		out = append(out, &cloned)
	}
	return out
}

func cloneResult(result *sdkprotocol.Result) *sdkprotocol.Result {
	if result == nil {
		return nil
	}
	cloned := *result
	if result.KeyShare != nil {
		keyShare := *result.KeyShare
		keyShare.PublicKey = append([]byte(nil), result.KeyShare.PublicKey...)
		cloned.KeyShare = &keyShare
	}
	if result.Signature != nil {
		signature := *result.Signature
		signature.Signature = append([]byte(nil), result.Signature.Signature...)
		signature.SignatureRecovery = append([]byte(nil), result.Signature.SignatureRecovery...)
		signature.R = append([]byte(nil), result.Signature.R...)
		signature.S = append([]byte(nil), result.Signature.S...)
		signature.SignedInput = append([]byte(nil), result.Signature.SignedInput...)
		signature.PublicKey = append([]byte(nil), result.Signature.PublicKey...)
		cloned.Signature = &signature
	}
	return &cloned
}

func cloneKeyMap(src map[string][]byte) map[string][]byte {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(src))
	for key, value := range src {
		out[key] = append([]byte(nil), value...)
	}
	return out
}
