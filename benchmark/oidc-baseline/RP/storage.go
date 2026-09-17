package rp

import (
	"encoding/gob"
	"sync"
)

// rpUser 表示 RP 视角下的用户基本信息（IdP 颁发的 sub + 本地缓存信息）
type rpUser struct {
	UID         string // Broker / IdP 侧的用户唯一标识（或本地 UID，看你设计）
	Username    string
	Email       string
	Sub         string // OIDC 风格的 subject
	AccessToken string // 最近一次拿到的 access token（如有需要）
}

// 注册 rpUser 类型到 gob，以便 Fiber session 可以序列化/反序列化
func init() {
	gob.Register(rpUser{})
}

// RPUserState 表示“某个 AUID 对应的一整个会话状态”
type RPUserState struct {
	User        rpUser
	Ks          []byte // 与 IdP 的会话密钥
	AccessToken []byte // 和 IdP 通信时用到的 token / 密钥材料（按你实际语义）
}

// TempAAKEState 表示 AAKE（匿名认证密钥交换）阶段的临时状态
type TempAAKEState struct {
	Ks []byte // 与 IdP 的会话密钥（AAKE 阶段用）
}

//
// ========= Store：并发安全的内存存储 =========
//

// RPUserStateStore：按 AUID（或者 session_id）存储用户会话状态
type RPUserStateStore struct {
	mu       sync.RWMutex
	sessions map[string]*RPUserState // key: auid 或 session_id
}

func NewRPUserStateStore() *RPUserStateStore {
	return &RPUserStateStore{
		sessions: make(map[string]*RPUserState),
	}
}

func (s *RPUserStateStore) Save(auid string, state *RPUserState) {
	if auid == "" || state == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[auid] = state
}

func (s *RPUserStateStore) Get(auid string) (*RPUserState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.sessions[auid]
	return st, ok
}

func (s *RPUserStateStore) Delete(auid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, auid)
}

// TempAAKEStateStore：按 state（通常是 OIDC state 参数）存 AAKE 临时状态
type TempAAKEStateStore struct {
	mu       sync.RWMutex
	sessions map[string]*TempAAKEState // key: state
}

func NewTempAAKEStateStore() *TempAAKEStateStore {
	return &TempAAKEStateStore{
		sessions: make(map[string]*TempAAKEState),
	}
}

func (s *TempAAKEStateStore) Save(state string, stateData *TempAAKEState) {
	if state == "" || stateData == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[state] = stateData
}

func (s *TempAAKEStateStore) Get(state string) (*TempAAKEState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stateData, ok := s.sessions[state]
	return stateData, ok
}

func (s *TempAAKEStateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, state)
}

//
// ========= 聚合 Service：对外暴露更高层的操作 =========
//

type tempStorageService struct {
	userStates *RPUserStateStore
	aakeStates *TempAAKEStateStore
}

// NewTempStorageService 构造一个临时存储服务，负责管理：
//   - AUID -> RPUserState
//   - state -> TempAAKEState（AAKE 中间状态）
func NewTempStorageService() *tempStorageService {
	return &tempStorageService{
		userStates: NewRPUserStateStore(),
		aakeStates: NewTempAAKEStateStore(),
	}
}

// 封装一层，方便上层代码只依赖 tempStorageService

// 按 AUID 保存/更新一个用户的会话状态
func (s *tempStorageService) SaveUserState(auid string, state *RPUserState) {
	s.userStates.Save(auid, state)
}

// 按 AUID 获取会话状态
func (s *tempStorageService) GetUserState(auid string) (*RPUserState, bool) {
	return s.userStates.Get(auid)
}

// 按 AUID 删除会话状态（建议补一个，便于登出/过期清理）
func (s *tempStorageService) DeleteUserState(auid string) {
	s.userStates.Delete(auid)
}

// AAKE state 相关的简单转发
func (s *tempStorageService) SaveAAKEState(state string, data *TempAAKEState) {
	s.aakeStates.Save(state, data)
}

func (s *tempStorageService) GetAAKEState(state string) (*TempAAKEState, bool) {
	return s.aakeStates.Get(state)
}

func (s *tempStorageService) DeleteAAKEState(state string) {
	s.aakeStates.Delete(state)
}
