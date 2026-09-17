package idp

import (
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
	comm "secure-sso/internal/common"

	"github.com/gofiber/fiber/v2/middleware/session"
)

type tempStorageService struct {
	users           map[string]*User // index: uid
	sessions        *session.Store
	codes           *CodeStore
	empkeys         *AAKEKeyStore
	EmpKeyIdx       int
	opaqueMu        sync.RWMutex
	authorized_msgs *authorizedMessages
}

type OpaqueExchangeData struct {
	D_enc    string
	ACID     string
	UID      string
	Username string
	Scope    string
}

// AuthorizationCode 授权码及其元信息
type AuthorizationCode struct {
	Code      string
	OprfEnc   string
	ACID      string
	UID       string
	Username  string
	Scope     string
	ExpiresAt time.Time
	Used      bool
}

type AAKEKeyStore struct {
	mu   sync.Mutex
	keys map[string]*comm.AAKEEphemeralKey
}
type CodeStore struct {
	mu    sync.Mutex
	codes map[string]*AuthorizationCode // index: code
}

func NewCodeStore() *CodeStore {
	return &CodeStore{
		codes: make(map[string]*AuthorizationCode),
	}
}

// GenerateCode 生成随机授权码
func GenerateCode() (string, error) {
	b := make([]byte, 32) // 256-bit 随机数
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *CodeStore) GetCode(code string) (*AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ac, exists := s.codes[code]
	if !exists {
		return nil, errors.New("code not found")
	}
	if time.Now().After(ac.ExpiresAt) {
		delete(s.codes, code) // 删除过期的 code
		return nil, errors.New("code expired")
	}
	if ac.Used {
		return nil, errors.New("code already used")
	}
	return ac, nil
}

// SaveCode 保存授权码
func (s *CodeStore) SaveCode(d_enc, acid, uid, username, scope string, ttl time.Duration) (*AuthorizationCode, error) {
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
		Scope:     scope,
		ExpiresAt: time.Now().Add(ttl),
		Used:      false,
	}

	s.codes[code] = ac
	return ac, nil
}

func (s *CodeStore) DeleteCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.codes[code]; !exists {
		return
	}
	delete(s.codes, code)
}

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
func NewTempStorageService() *tempStorageService {
	return &tempStorageService{
		users: make(map[string]*User),
		codes: NewCodeStore(),
		empkeys: &AAKEKeyStore{
			keys: make(map[string]*comm.AAKEEphemeralKey),
		},
		sessions: session.New(session.Config{
			Expiration: 30 * time.Minute, // session 过期时间
		}),
		authorized_msgs: NewAuthorizedMessages(),
	}
}

func (s *tempStorageService) UseTestUsers() {
	path := idpUsersFile
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

type authorizedUserData struct {
	acid         string
	uid          string
	auid         string
	OprfEnc      string
	username     string
	scope        string
	IdToken      string
	AccessToken  string
	RefreshToken string
}

type authorizedMessages struct {
	mu       sync.RWMutex
	messages map[string]*list.List // index: uid
}

func NewAuthorizedMessages() *authorizedMessages {
	return &authorizedMessages{
		messages: make(map[string]*list.List),
	}
}

func (msg *authorizedMessages) Add(data *authorizedUserData) {
	msg.mu.Lock()
	defer msg.mu.Unlock()
	if data == nil {
		return
	}
	uid := data.uid
	if _, ok := msg.messages[uid]; !ok {
		msg.messages[uid] = list.New()
	}
	lst, ok := msg.messages[uid]
	if !ok {
		lst = list.New()
		msg.messages[uid] = lst
	}
	// 进行深拷贝并强制创建新的字符串副本以避免后续修改影响已存储的数据
	d := authorizedUserData{
		acid:         string([]byte(data.acid)),
		uid:          string([]byte(data.uid)),
		OprfEnc:      string([]byte(data.OprfEnc)),
		username:     string([]byte(data.username)),
		scope:        string([]byte(data.scope)),
		IdToken:      string([]byte(data.IdToken)),
		AccessToken:  string([]byte(data.AccessToken)),
		RefreshToken: string([]byte(data.RefreshToken)),
	}
	lst.PushBack(d)
}

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
			// 进行深拷贝并强制创建新的字符串副本以避免内存安全问题
			d := &authorizedUserData{
				acid:         string([]byte(data.acid)),
				uid:          string([]byte(data.uid)),
				OprfEnc:      string([]byte(data.OprfEnc)),
				username:     string([]byte(data.username)),
				scope:        string([]byte(data.scope)),
				IdToken:      string([]byte(data.IdToken)),
				AccessToken:  string([]byte(data.AccessToken)),
				RefreshToken: string([]byte(data.RefreshToken)),
			}
			out = append(out, d)
		}
	}
	return out
}

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

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Sub      string `json:"sub"`
	Email    string `json:"email"`
}
