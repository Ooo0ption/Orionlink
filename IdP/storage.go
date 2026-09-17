// In-memory IdP state: users, ephemeral AAKA keys, authorization codes and the
// per-user authorization records.
package idp

import (
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	comm "secure-sso/internal/common"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2/middleware/session"
)

// tempStorageService bundles the IdP's in-memory state: users, browser sessions,
// authorization codes, the AAKA ephemeral key pool and authorization records.
type tempStorageService struct {
	users           map[string]*User
	sessions        *session.Store
	codes           *CodeStore
	empkeys         *AAKEKeyStore
	EmpKeyIdx       int
	opaqueMu        sync.RWMutex
	authorized_msgs *authorizedMessages
}

// OpaqueExchangeData carries the TCA-encrypted D value alongside the session
// context it was authorized in.
type OpaqueExchangeData struct {
	D_enc    string
	ACID     string
	UID      string
	Username string
	Scope    string
}

// AuthorizationCode is an issued code together with the authorized user data it
// stands for.
type AuthorizationCode struct {
	Code      string
	OprfEnc   string
	ACID      string
	UID       string
	Username  string
	Email     string
	Scope     string
	ExpiresAt time.Time
	Used      bool
}

// AAKEKeyStore is the pool of pre-generated AAKA ephemeral keys, keyed by id.
type AAKEKeyStore struct {
	mu   sync.Mutex
	keys map[string]*comm.AAKEEphemeralKey
}

// CodeStore holds the authorization codes still open for redemption.
type CodeStore struct {
	mu    sync.Mutex
	codes map[string]*AuthorizationCode
}

// NewCodeStore returns an empty authorization-code store.
func NewCodeStore() *CodeStore {
	return &CodeStore{
		codes: make(map[string]*AuthorizationCode),
	}
}

// GenerateCode returns a fresh random authorization code.
func GenerateCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GetCode returns an unused, unexpired authorization code, dropping it if it has
// expired.
func (s *CodeStore) GetCode(code string) (*AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ac, exists := s.codes[code]
	if !exists {
		return nil, errors.New("code not found")
	}
	if time.Now().After(ac.ExpiresAt) {
		delete(s.codes, code)
		return nil, errors.New("code expired")
	}
	if ac.Used {
		return nil, errors.New("code already used")
	}
	return ac, nil
}

// SaveCode creates and stores an authorization code for an authorized session.
func (s *CodeStore) SaveCode(d_enc, acid, uid, username, email, scope string, ttl time.Duration) (*AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	code, err := GenerateCode()
	if err != nil {
		return nil, err
	}

	ac := &AuthorizationCode{
		Code:      code,
		OprfEnc:   d_enc,
		ACID:      acid,
		UID:       uid,
		Username:  username,
		Email:     email,
		Scope:     scope,
		ExpiresAt: time.Now().Add(ttl),
		Used:      false,
	}

	s.codes[code] = ac
	return ac, nil
}

// DeleteCode drops a code from the store, burning it after redemption.
func (s *CodeStore) DeleteCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.codes[code]; !exists {
		return
	}
	delete(s.codes, code)
}

// getEmpKey looks up an AAKA ephemeral key pair by its id.
func (s *AAKEKeyStore) getEmpKey(id string) (*comm.AAKEEphemeralKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		s.keys = make(map[string]*comm.AAKEEphemeralKey)
	}
	if key, ok := s.keys[id]; ok {
		return key, nil
	}
	return nil, errors.New("key not found")

}

// NewTempStorageService returns the IdP's in-memory stores with a 30-minute
// session cookie configured.
func NewTempStorageService() *tempStorageService {
	return &tempStorageService{
		users: make(map[string]*User),
		codes: NewCodeStore(),
		empkeys: &AAKEKeyStore{
			keys: make(map[string]*comm.AAKEEphemeralKey),
		},
		sessions: session.New(session.Config{
			Expiration:     30 * time.Minute,
			CookieHTTPOnly: true,
			KeyLookup:      "cookie:idp_session",
		}),
		authorized_msgs: NewAuthorizedMessages(),
	}
}

// UseTestUsers loads the demo accounts from the IdP's users file, if present.
func (s *tempStorageService) UseTestUsers() {
	path := idpUsersFile()
	if b, err := os.ReadFile(path); err == nil {
		var arr []User
		if err := json.Unmarshal(b, &arr); err == nil {
			for _, u := range arr {
				s.users[u.Username] = &u
			}
		}
		return
	}
}

// authorizedUserData is one issuance record: the RP pseudonym acid, the user's
// identifiers, the granted scope and the tokens handed out for it.
type authorizedUserData struct {
	acid         string
	uid          string
	auid         string
	OprfEnc      string
	username     string
	email        string
	scope        string
	IdToken      string
	AccessToken  string
	RefreshToken string
}

// authorizedMessages holds each user's authorization records, keyed by uid.
type authorizedMessages struct {
	mu       sync.RWMutex
	messages map[string]*list.List
}

// NewAuthorizedMessages returns an empty authorization-record store.
func NewAuthorizedMessages() *authorizedMessages {
	return &authorizedMessages{
		messages: make(map[string]*list.List),
	}
}

// Add appends one authorization record to its user's list.
func (msg *authorizedMessages) Add(data *authorizedUserData) {
	msg.mu.Lock()
	defer msg.mu.Unlock()
	if data == nil {
		return
	}
	uid := data.uid
	lst, ok := msg.messages[uid]
	if !ok {
		lst = list.New()
		msg.messages[uid] = lst
	}
	lst.PushBack(*data)
}

// GetAll returns copies of every authorization record held for one user.
func (msg *authorizedMessages) GetAll(uid *string) []*authorizedUserData {
	msg.mu.RLock()
	defer msg.mu.RUnlock()
	if uid == nil {
		return nil
	}
	lst, ok := msg.messages[*uid]
	if !ok || lst.Len() == 0 {
		return nil
	}
	var out []*authorizedUserData
	for e := lst.Front(); e != nil; e = e.Next() {
		if data, ok := e.Value.(authorizedUserData); ok {
			d := data
			out = append(out, &d)
		}
	}
	return out
}

// Delete removes the user's authorization record for one acid.
func (msg *authorizedMessages) Delete(uid *string, acid *string) {
	msg.mu.Lock()
	defer msg.mu.Unlock()
	if uid == nil || acid == nil {
		return
	}
	lst, ok := msg.messages[*uid]
	if !ok {
		return
	}
	for e := lst.Front(); e != nil; e = e.Next() {
		if data, ok := e.Value.(authorizedUserData); ok && data.acid == *acid {
			lst.Remove(e)
			break
		}
	}
}

// User is one IdP account as stored in the users file.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Sub      string `json:"sub"`
	Email    string `json:"email"`
}
