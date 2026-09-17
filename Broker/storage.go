// In-memory Broker state: users, RP identities, authorization codes and
// per-session data.
package broker

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	comm "secure-sso/internal/common"
	"secure-sso/lib"
	"sync"
	"time"

	"github.com/cloudflare/circl/ecc/bls12381"
)

const (
	defaultAuthCodeTTL = 500 * time.Minute
)

// Tokens is the set of tokens the broker relays and stores for one user at one RP.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

// User is one user's token state at one RP.
type User struct {
	UID   string
	Token *Tokens
}

// AuthorizationCode is an issued code and its metadata, redeemable for tokens.
type AuthorizationCode struct {
	Code      string
	UserID    string
	RPID      string
	Tokens    *Tokens
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}

// UserStore keeps the token state of one RP's users, keyed by uid_rp.
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User
}

// NewUserStore returns an empty per-RP user store.
func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*User),
	}
}

// GetUser returns the stored user for uid_rp, if any.
func (s *UserStore) GetUser(uid string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[uid]
	return u, ok
}

// SaveUser inserts or replaces the token state of one user.
func (s *UserStore) SaveUser(user *User) {
	if user == nil || user.UID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.UID] = user
}

// rpIdentity is everything the broker knows about a registered RP: its ticket
// id, DomainCredential, callback, scopes, users and DH prekeys.
type rpIdentity struct {
	TID         string
	DomainCred  *comm.DomainCredential
	CallbackURL string
	Scopes      []string
	UserStore   *UserStore
	RPDHPks     [][]byte
}

// CodeStore holds the broker-issued authorization codes still open for redemption.
type CodeStore struct {
	mu    sync.RWMutex
	codes map[string]*AuthorizationCode
}

// NewCodeStore returns an empty authorization-code store.
func NewCodeStore() *CodeStore {
	return &CodeStore{
		codes: make(map[string]*AuthorizationCode),
	}
}

// GenerateCode returns a fresh 256-bit authorization code.
func GenerateCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IssueCode creates and stores an authorization code for the given user and RP.
func (s *CodeStore) IssueCode(userID, rpid string, tokens *Tokens) (string, error) {
	code, err := GenerateCode()
	if err != nil {
		return "", err
	}

	now := time.Now()
	ac := &AuthorizationCode{
		Code:      code,
		UserID:    userID,
		RPID:      rpid,
		Tokens:    tokens,
		CreatedAt: now,
		ExpiresAt: now.Add(defaultAuthCodeTTL),
		Used:      false,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = ac

	return code, nil
}

// GetCode looks up a code and marks it used, so a code cannot be replayed.
func (s *CodeStore) GetCode(code string) (*AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ac, ok := s.codes[code]
	if !ok {
		return nil, errors.New("authorization code not found")
	}

	if time.Now().After(ac.ExpiresAt) {
		delete(s.codes, code)
		return nil, errors.New("authorization code expired")
	}

	if ac.Used {
		return nil, errors.New("authorization code already used")
	}

	ac.Used = true
	delete(s.codes, code)

	return ac, nil
}

// DeleteCode drops a code from the store.
func (s *CodeStore) DeleteCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
}

// brokerSessionData is the per-login state: the randomization scalars t and k,
// the randomized credential (acid) and the originating RP and OAuth state.
type brokerSessionData struct {
	t       *bls12381.Scalar
	k       *bls12381.Scalar
	randSig *lib.PSSignMsg
	tid     string
	state   string
}

// tempStorageService bundles the broker's in-memory stores: registered RPs,
// issued codes and live login sessions.
type tempStorageService struct {
	rpIdentity  map[string]*rpIdentity
	codes       *CodeStore
	sessionData map[string]*brokerSessionData
}

// NewTempStorageService returns the broker's in-memory stores, all empty.
func NewTempStorageService() *tempStorageService {
	return &tempStorageService{
		rpIdentity:  make(map[string]*rpIdentity),
		codes:       NewCodeStore(),
		sessionData: make(map[string]*brokerSessionData),
	}
}
