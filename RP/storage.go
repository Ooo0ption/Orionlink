// In-memory RP state: per-user session records and the transient AAKA state kept
// between the login redirect and the callback.
package rp

import (
	"encoding/gob"
	"sync"
)

// rpUser is the RP's view of a user: the IdP-issued sub plus locally cached fields.
type rpUser struct {
	UID         string
	Username    string
	Email       string
	Sub         string
	AccessToken string
}

// init registers rpUser with gob so it can be stored in a Fiber session.
func init() {
	gob.Register(rpUser{})
}

// RPUserState is the full session state behind one AUID.
type RPUserState struct {
	User        rpUser
	Ks          []byte
	AccessToken []byte
}

// TempAAKEState is the transient state kept during the AAKA exchange.
type TempAAKEState struct {
	Ks []byte
}

// RPUserStateStore keeps user session state keyed by AUID.
type RPUserStateStore struct {
	mu       sync.RWMutex
	sessions map[string]*RPUserState
}

// NewRPUserStateStore returns an empty user-session store.
func NewRPUserStateStore() *RPUserStateStore {
	return &RPUserStateStore{
		sessions: make(map[string]*RPUserState),
	}
}

// Save stores or replaces the session state behind one AUID.
func (s *RPUserStateStore) Save(auid string, state *RPUserState) {
	if auid == "" || state == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[auid] = state
}

// Get returns the session state behind one AUID.
func (s *RPUserStateStore) Get(auid string) (*RPUserState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.sessions[auid]
	return st, ok
}

// Delete drops the session state behind one AUID.
func (s *RPUserStateStore) Delete(auid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, auid)
}

// TempAAKEStateStore keeps AAKA transient state keyed by the OIDC state parameter.
type TempAAKEStateStore struct {
	mu       sync.RWMutex
	sessions map[string]*TempAAKEState
}

// NewTempAAKEStateStore returns an empty store for AAKA transient state.
func NewTempAAKEStateStore() *TempAAKEStateStore {
	return &TempAAKEStateStore{
		sessions: make(map[string]*TempAAKEState),
	}
}

// Save records the AAKA state (K_S) for one login, keyed by the OAuth state.
func (s *TempAAKEStateStore) Save(state string, stateData *TempAAKEState) {
	if state == "" || stateData == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[state] = stateData
}

// Get returns the AAKA state recorded for one OAuth state value.
func (s *TempAAKEStateStore) Get(state string) (*TempAAKEState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stateData, ok := s.sessions[state]
	return stateData, ok
}

// Delete drops the AAKA state for one OAuth state value.
func (s *TempAAKEStateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, state)
}

// tempStorageService bundles the RP's two in-memory stores.
type tempStorageService struct {
	userStates *RPUserStateStore
	aakeStates *TempAAKEStateStore
}

// NewTempStorageService builds the RP's in-memory store for user session state and
// AAKA transient state.
func NewTempStorageService() *tempStorageService {
	return &tempStorageService{
		userStates: NewRPUserStateStore(),
		aakeStates: NewTempAAKEStateStore(),
	}
}

// SaveUserState stores or replaces the session state for an AUID.
func (s *tempStorageService) SaveUserState(auid string, state *RPUserState) {
	s.userStates.Save(auid, state)
}

// GetUserState returns the session state for an AUID.
func (s *tempStorageService) GetUserState(auid string) (*RPUserState, bool) {
	return s.userStates.Get(auid)
}

// DeleteUserState drops the session state for an AUID.
func (s *tempStorageService) DeleteUserState(auid string) {
	s.userStates.Delete(auid)
}

// SaveAAKEState stores the AAKA transient state for an OIDC state value.
func (s *tempStorageService) SaveAAKEState(state string, data *TempAAKEState) {
	s.aakeStates.Save(state, data)
}

// GetAAKEState returns the AAKA transient state for an OAuth state value.
func (s *tempStorageService) GetAAKEState(state string) (*TempAAKEState, bool) {
	return s.aakeStates.Get(state)
}

// DeleteAAKEState drops the AAKA transient state for an OAuth state value.
func (s *tempStorageService) DeleteAAKEState(state string) {
	s.aakeStates.Delete(state)
}
