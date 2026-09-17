// RP persistence: runtime configuration, credential and refresh key material, and
// the on-disk registration record.
package rp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
)

// Runtime file locations, resolved through internal/config.
func rpRuntimeConfFile() string { return orionconf.Get().RoleConfigPath("RP", "config.json") }
func rpKeyStorageFile() string  { return orionconf.Get().RoleConfigPath("RP", "key_storage.json") }
func rpRegDataFile() string {
	return orionconf.Get().RoleConfigPath("RP", "registration_data.json")
}

// SecureSSOConfig is the set of absolute IdP and broker endpoint URLs the RP
// calls at runtime, derived from RuntimeConfig.
type SecureSSOConfig struct {
	IdPUserInfoURL     string
	IdPRegisterURL     string
	IdPPubKeyURL       string
	EmpKeyURL          string
	BrokerRegisterURL  string
	BrokerAuthorizeURL string
	BrokerTokenURL     string
	BrokerJWKSURL      string
	RedirectURI        string
	BrokerRefreshURL   string
}

// IdPConfig carries the two ways the IdP can be reached (host and container).
type IdPConfig struct {
	IdPURL       string
	IdPDockerURL string
}

// RuntimeConfig mirrors RP/config.json: the listen port, the callback URI and
// the protocol paths of the IdP and broker endpoints.
type RuntimeConfig struct {
	Port                 string
	OIDCRedirectURI      string
	SecureSSORedirectURI string
	IdPConfig            struct {
		BrowserReachURL string
		ServerReachURL  string
		OIDCConfig      struct {
			AuthorizePath string
			TokenPath     string
			JWKSPath      string
			UserInfoPath  string
			RegisterPath  string
		}
		SecureSSOConfig struct {
			PubKeyPath   string
			RegisterPath string
			EmpKeyPath   string
			UserInfoPath string
		}
	}
	BrokerConfig struct {
		BrowserReachURL string
		ServerReachURL  string
		OIDCConfig      struct {
			AuthorizePath string
			TokenPath     string
			JWKSPath      string
			UserInfoPath  string
			RegisterPath  string
		}
		SecureSSOConfig struct {
			JWKSPath      string
			RegisterPath  string
			AuthorizePath string
			PubKeyPath    string
			TokenPath     string
			RefreshPath   string
		}
	}
}

// Load reads the RP's config.json from path.
func (c *RuntimeConfig) Load(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(c)
}

// ApplyEnv overlays the deployment configuration onto the values loaded from
// config.json: the JSON supplies the protocol paths, ORION_* the addresses.
func (c *RuntimeConfig) ApplyEnv(cfg *orionconf.Config) {
	c.Port = strings.TrimPrefix(cfg.ListenAddr("rp"), ":")
	c.SecureSSORedirectURI = cfg.RP.Browser + "/ssso/callback"

	c.IdPConfig.BrowserReachURL = cfg.IdP.Browser
	c.IdPConfig.ServerReachURL = cfg.IdP.Server
	c.BrokerConfig.BrowserReachURL = cfg.Broker.Browser
	c.BrokerConfig.ServerReachURL = cfg.Broker.Server
}

// GetSecureSSOConfig joins the reachable base URLs with the configured protocol
// paths into the absolute endpoints the RP calls.
func (c *RuntimeConfig) GetSecureSSOConfig() *SecureSSOConfig {
	conf := &SecureSSOConfig{
		BrokerAuthorizeURL: c.BrokerConfig.BrowserReachURL + c.BrokerConfig.SecureSSOConfig.AuthorizePath,
		IdPUserInfoURL:     c.IdPConfig.BrowserReachURL + c.IdPConfig.SecureSSOConfig.UserInfoPath,
		IdPRegisterURL:     c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.RegisterPath,
		IdPPubKeyURL:       c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.PubKeyPath,
		BrokerRegisterURL:  c.BrokerConfig.ServerReachURL + c.BrokerConfig.SecureSSOConfig.RegisterPath,
		BrokerTokenURL:     c.BrokerConfig.ServerReachURL + c.BrokerConfig.SecureSSOConfig.TokenPath,
		BrokerJWKSURL:      c.BrokerConfig.ServerReachURL + c.BrokerConfig.SecureSSOConfig.JWKSPath,
		RedirectURI:        c.SecureSSORedirectURI,
		EmpKeyURL:          c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.EmpKeyPath,
		BrokerRefreshURL:   c.BrokerConfig.ServerReachURL + c.BrokerConfig.SecureSSOConfig.RefreshPath,
	}
	return conf
}

// RPKeyStorage is the layout of the RP's key_storage.json.
type RPKeyStorage struct {
	IdPAAKEPk   *IdPAAKEPkData  `json:"idp_aake_pk,omitempty"`
	IdentitySk  *IdentitySkData `json:"identity_sk,omitempty"`
	SessionKS   *SessionKSData  `json:"session_ks,omitempty"`
	RefreshKeys []string        `json:"refresh_keys,omitempty"`
}

// IdPAAKEPkData is the persisted IdP AAKA public key, hex-encoded.
type IdPAAKEPkData struct {
	PKHex string `json:"pk_hex"`
}

// IdentitySkData is the persisted RP identity secret, hex-encoded.
type IdentitySkData struct {
	SKHex string `json:"sk_hex"`
}

// SessionKSData is the persisted AAKA session key, hex-encoded.
type SessionKSData struct {
	KSHex string `json:"ks_hex"`
}

var sessionKSMutex sync.Mutex

// saveSessionKS persists the AAKA session key K_S so the refresh ratchet can seed
// its root key from it.
func saveSessionKS(ks []byte) error {
	if len(ks) == 0 {
		return nil
	}
	sessionKSMutex.Lock()
	defer sessionKSMutex.Unlock()
	storage, err := loadRPKeyStorage()
	if err != nil {
		storage = &RPKeyStorage{}
	}
	storage.SessionKS = &SessionKSData{KSHex: hex.EncodeToString(ks)}
	return saveRPKeyStorage(storage)
}

// loadSessionKS reads the persisted K_S, falling back to the shared bootstrap
// value when no session has been persisted.
func loadSessionKS() []byte {
	storage, err := loadRPKeyStorage()
	if err != nil || storage.SessionKS == nil || storage.SessionKS.KSHex == "" {
		return append([]byte(nil), comm.BootstrapRefreshKS...)
	}
	ks, err := hex.DecodeString(storage.SessionKS.KSHex)
	if err != nil || len(ks) == 0 {
		return append([]byte(nil), comm.BootstrapRefreshKS...)
	}
	return ks
}

// saveRefreshKeys persists the refresh-ratchet DH private keys, keeping them
// consistent across restarts with the public keys the broker stored.
func saveRefreshKeys(rsk []*bls12381.Scalar) error {
	if len(rsk) == 0 {
		return nil
	}
	sessionKSMutex.Lock()
	defer sessionKSMutex.Unlock()
	storage, err := loadRPKeyStorage()
	if err != nil {
		storage = &RPKeyStorage{}
	}
	hexes := make([]string, 0, len(rsk))
	for _, sk := range rsk {
		hexes = append(hexes, hex.EncodeToString(comm.ScalarToBytes(sk)))
	}
	storage.RefreshKeys = hexes
	return saveRPKeyStorage(storage)
}

// loadRefreshKeys returns the persisted refresh DH private keys, or nil if none.
func loadRefreshKeys() []*bls12381.Scalar {
	storage, err := loadRPKeyStorage()
	if err != nil || len(storage.RefreshKeys) == 0 {
		return nil
	}
	out := make([]*bls12381.Scalar, 0, len(storage.RefreshKeys))
	for _, h := range storage.RefreshKeys {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil
		}
		sk, err := comm.BytesToScalar(b)
		if err != nil {
			return nil
		}
		out = append(out, sk)
	}
	return out
}

// loadRPKeyStorage reads the RP's key material, returning an empty record when
// the file does not exist yet.
func loadRPKeyStorage() (*RPKeyStorage, error) {
	data, err := os.ReadFile(rpKeyStorageFile())
	if err != nil {
		if os.IsNotExist(err) {
			return &RPKeyStorage{}, nil
		}
		return nil, fmt.Errorf("read key storage file: %w", err)
	}

	var storage RPKeyStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return nil, fmt.Errorf("unmarshal key storage: %w", err)
	}

	return &storage, nil
}

// saveRPKeyStorage writes the key material back to disk with 0600 permissions.
func saveRPKeyStorage(storage *RPKeyStorage) error {
	jsonData, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key storage: %w", err)
	}
	if err := os.WriteFile(rpKeyStorageFile(), jsonData, 0600); err != nil {
		return fmt.Errorf("write key storage file: %w", err)
	}
	return nil
}

// loadIdPAAKEPk restores the IdP's AAKA public key from key storage.
func loadIdPAAKEPk() (*bls12381.G1, error) {
	storage, err := loadRPKeyStorage()
	if err != nil {
		return nil, err
	}
	if storage.IdPAAKEPk == nil || storage.IdPAAKEPk.PKHex == "" {
		return nil, fmt.Errorf("idp aake pk not found in storage")
	}
	pkBytes, err := hex.DecodeString(storage.IdPAAKEPk.PKHex)
	if err != nil {
		return nil, fmt.Errorf("decode PK hex: %w", err)
	}
	pk, err := comm.BytesToG1(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("convert PK to G1: %w", err)
	}
	return pk, nil
}

// saveIdPAAKEPk persists the IdP's AAKA public key.
func saveIdPAAKEPk(pk *bls12381.G1) error {
	storage, err := loadRPKeyStorage()
	if err != nil {
		storage = &RPKeyStorage{}
	}
	pkBytes := comm.G1ToBytes(pk)
	storage.IdPAAKEPk = &IdPAAKEPkData{PKHex: hex.EncodeToString(pkBytes)}
	return saveRPKeyStorage(storage)
}

// loadIdentitySk restores the RP's identity secret from key storage.
func loadIdentitySk() (*bls12381.Scalar, error) {
	storage, err := loadRPKeyStorage()
	if err != nil {
		return nil, err
	}
	if storage.IdentitySk == nil || storage.IdentitySk.SKHex == "" {
		return nil, fmt.Errorf("identity sk not found in storage")
	}
	skBytes, err := hex.DecodeString(storage.IdentitySk.SKHex)
	if err != nil {
		return nil, fmt.Errorf("decode SK hex: %w", err)
	}
	sk, err := comm.BytesToScalar(skBytes)
	if err != nil {
		return nil, fmt.Errorf("convert SK to scalar: %w", err)
	}
	return sk, nil
}

// saveIdentitySk persists the RP's identity secret.
func saveIdentitySk(sk *bls12381.Scalar) error {
	storage, err := loadRPKeyStorage()
	if err != nil {
		storage = &RPKeyStorage{}
	}
	skBytes := comm.ScalarToBytes(sk)
	storage.IdentitySk = &IdentitySkData{SKHex: hex.EncodeToString(skBytes)}
	return saveRPKeyStorage(storage)
}

// RegistrationData is the RP's on-disk registration record: whether it has
// registered with the IdP and broker, its tid, and both credentials.
type RegistrationData struct {
	IDPRegistered    bool            `json:"idp_registered"`
	BrokerRegistered bool            `json:"broker_registered"`
	TID              string          `json:"tid"`
	DomainCred       *DomainCredData `json:"domain_cred,omitempty"`
	SecretCred       *SecretCredData `json:"secret_cred,omitempty"`
	Timestamp        string          `json:"timestamp"`
}

// DomainCredData is the serialized DomainCredential.
type DomainCredData struct {
	Domain []byte `json:"domain"`
	Sigma  []byte `json:"sigma"`
}

// SecretCredData is the serialized SecretCredential.
type SecretCredData struct {
	Domain     []byte `json:"domain"`
	IdentitySk []byte `json:"identity_sk"`
	SigmaBar   []byte `json:"sigma_bar"`
}

var registrationMutex sync.Mutex

// saveRegistrationData writes the RP's registration state and both credentials
// to disk, so a restart does not require re-registering.
func (s *RPServer) saveRegistrationData() error {
	registrationMutex.Lock()
	defer registrationMutex.Unlock()

	data := RegistrationData{
		IDPRegistered:    s.DomainCred != nil && s.DomainCred.Sigma != nil && s.DomainCred.Sigma.Sigma1 != nil,
		BrokerRegistered: s.TID != "",
		TID:              s.TID,
		Timestamp:        time.Now().Format(time.RFC3339),
	}

	if s.DomainCred != nil {
		var sigmaBytes []byte
		if s.DomainCred.Sigma != nil {
			sigmaBytes, _ = s.DomainCred.Sigma.ToJSON()
		}
		data.DomainCred = &DomainCredData{
			Domain: s.DomainCred.Domain,
			Sigma:  sigmaBytes,
		}
	}

	if s.SecretCred != nil {
		var sigmaBarBytes []byte
		var identitySkBytes []byte
		if s.SecretCred.SigmaBar != nil {
			sigmaBarBytes, _ = s.SecretCred.SigmaBar.ToJSON()
		}
		if s.SecretCred.IdentitySk != nil {
			identitySkBytes = comm.ScalarToBytes(s.SecretCred.IdentitySk)
		}
		data.SecretCred = &SecretCredData{
			Domain:     s.SecretCred.Domain,
			IdentitySk: identitySkBytes,
			SigmaBar:   sigmaBarBytes,
		}
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal registration data: %w", err)
	}
	if err := os.WriteFile(rpRegDataFile(), jsonData, 0644); err != nil {
		return fmt.Errorf("write registration file: %w", err)
	}
	return nil
}

// loadRegistrationData reads the registration record and restores the tid and
// both credentials onto the server.
func (s *RPServer) loadRegistrationData() (*RegistrationData, error) {
	registrationMutex.Lock()
	defer registrationMutex.Unlock()

	data, err := os.ReadFile(rpRegDataFile())
	if err != nil {
		if os.IsNotExist(err) {
			return &RegistrationData{}, nil
		}
		return nil, fmt.Errorf("read registration file: %w", err)
	}

	var regData RegistrationData
	if err := json.Unmarshal(data, &regData); err != nil {
		return nil, fmt.Errorf("unmarshal registration data: %w", err)
	}

	if regData.DomainCred != nil {
		if s.DomainCred == nil {
			s.DomainCred = &comm.DomainCredential{}
		}
		s.DomainCred.Domain = regData.DomainCred.Domain
		if len(regData.DomainCred.Sigma) > 0 {
			s.DomainCred.Sigma = &lib.PSSignMsg{}
			if err := s.DomainCred.Sigma.FromJSON(regData.DomainCred.Sigma); err != nil {
				return nil, fmt.Errorf("restore domain cred sigma: %w", err)
			}
		}
	}

	if regData.SecretCred != nil {
		if s.SecretCred == nil {
			s.SecretCred = &comm.SecretCredential{}
		}
		s.SecretCred.Domain = regData.SecretCred.Domain
		if len(regData.SecretCred.IdentitySk) > 0 {
			sk, err := comm.BytesToScalar(regData.SecretCred.IdentitySk)
			if err != nil {
				return nil, fmt.Errorf("restore secret cred identity sk: %w", err)
			}
			s.SecretCred.IdentitySk = sk
		}
		if len(regData.SecretCred.SigmaBar) > 0 {
			s.SecretCred.SigmaBar = &lib.PSSignMsg{}
			if err := s.SecretCred.SigmaBar.FromJSON(regData.SecretCred.SigmaBar); err != nil {
				return nil, fmt.Errorf("restore secret cred sigma bar: %w", err)
			}
		}
	}

	if regData.TID != "" {
		s.TID = regData.TID
	}

	return &regData, nil
}

// handleRegistrationStatus reports whether the RP has registered with the IdP
// and the broker, for the registration page to poll.
func (s *RPServer) handleRegistrationStatus(c *fiber.Ctx) error {
	regData, err := s.loadRegistrationData()
	if err != nil {
		return s.handleError(c, comm.InternalError, "failed to load registration data: "+err.Error())
	}

	return c.JSON(fiber.Map{
		"registered":       regData.IDPRegistered && regData.BrokerRegistered,
		"idpRegistered":    regData.IDPRegistered,
		"brokerRegistered": regData.BrokerRegistered,
		"tid":              regData.TID,
	})
}
