// Broker persistence: runtime configuration loading and the on-disk RP
// registration records.
package broker

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/lib"
)

// Runtime file locations, resolved through internal/config.
func brokerRuntimeConfFile() string {
	return orionconf.Get().RoleConfigPath("Broker", "config.json")
}
func brokerRegDataFile() string {
	return orionconf.Get().RoleConfigPath("Broker", "registration_data.json")
}

// SecureSSOConfig is the set of absolute IdP and RP endpoint URLs the broker
// calls at runtime, derived from RuntimeConfig.
type SecureSSOConfig struct {
	IdPURL          string
	IdPAuthorizeURL string
	IdPTokenURL     string
	IdPJWKSURL      string
	IdPPubKeyURL    string
	IdPCallbackURL  string
	IdPMacURL       string
	RPURL           string
	RPPoKURL        string
	RPUnblindURL    string
	RPMacURL        string
	IdPRefreshURL   string
}

// IdPConfig carries the two ways the IdP can be reached (host and container).
type IdPConfig struct {
	IdPURL       string
	IdPDockerURL string
}

// RuntimeConfig mirrors Broker/config.json: issuer, port and the protocol paths
// of the IdP and RP endpoints.
type RuntimeConfig struct {
	Issuer       string
	DockerIssuer string
	Port         string
	IdPConfig    struct {
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
			AuthorizePath string
			TokenPath     string
			JWKSPath      string
			PubKeyPath    string
			CallbackPath  string
			MacPath       string
			RefreshPath   string
		}
	}
	RPConfig struct {
		BrowserReachURL string
		ServerReachURL  string
		PoKPath         string
		MacPath         string
	}
}

// Load reads the broker's config.json from path.
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
	c.Port = strings.TrimPrefix(cfg.ListenAddr("broker"), ":")
	c.Issuer = cfg.Broker.Browser
	c.DockerIssuer = cfg.Broker.Server

	c.IdPConfig.BrowserReachURL = cfg.IdP.Browser
	c.IdPConfig.ServerReachURL = cfg.IdP.Server
	c.RPConfig.BrowserReachURL = cfg.RP.Browser
	c.RPConfig.ServerReachURL = cfg.RP.Server
}

// GetSecureSSOConfig joins the reachable base URLs with the configured protocol
// paths into the absolute endpoints the broker calls.
func (c *RuntimeConfig) GetSecureSSOConfig() *SecureSSOConfig {
	conf := &SecureSSOConfig{
		IdPAuthorizeURL: c.IdPConfig.BrowserReachURL + c.IdPConfig.SecureSSOConfig.AuthorizePath,
		IdPURL:          c.IdPConfig.ServerReachURL,
		IdPTokenURL:     c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.TokenPath,
		IdPJWKSURL:      c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.JWKSPath,
		IdPPubKeyURL:    c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.PubKeyPath,
		IdPCallbackURL:  c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.CallbackPath,
		IdPMacURL:       c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.MacPath,
		RPURL:           c.RPConfig.ServerReachURL,
		RPPoKURL:        c.RPConfig.ServerReachURL + c.RPConfig.PoKPath,
		RPUnblindURL:    c.RPConfig.ServerReachURL + "/ssso/login/aake/unblind",
		RPMacURL:        c.RPConfig.ServerReachURL + c.RPConfig.MacPath,
		IdPRefreshURL:   c.IdPConfig.ServerReachURL + c.IdPConfig.SecureSSOConfig.RefreshPath,
	}
	return conf
}

// BrokerRegistrationData is the on-disk record of every RP registered with this
// broker.
type BrokerRegistrationData struct {
	RegisteredRPs []BrokerRPInfo `json:"registered_rps"`
	Timestamp     string         `json:"timestamp"`
}

// BrokerRPInfo is one RP's persisted registration record; Sigma is the
// serialized PS signature of its DomainCredential.
type BrokerRPInfo struct {
	TID         string   `json:"tid"`
	Domain      []byte   `json:"domain"`
	CallbackURL string   `json:"callback_url"`
	Scopes      []string `json:"scopes"`
	Sigma       []byte   `json:"sigma,omitempty"`
	RPDHPks     [][]byte `json:"rp_dh_pks,omitempty"`
	Timestamp   string   `json:"timestamp"`
}

var brokerRegistrationMutex sync.Mutex

// saveRegistrationData inserts or updates one RP's record in the registration
// file, keyed by tid.
func (s *BrokerServer) saveRegistrationData(tid string, rpInfo *rpIdentity) error {
	brokerRegistrationMutex.Lock()
	defer brokerRegistrationMutex.Unlock()

	var data BrokerRegistrationData
	if fileData, err := os.ReadFile(brokerRegDataFile()); err == nil {
		_ = json.Unmarshal(fileData, &data)
	}

	exists := false
	var sigmaBytes []byte
	if rpInfo.DomainCred != nil && rpInfo.DomainCred.Sigma != nil {
		sigmaBytes, _ = rpInfo.DomainCred.Sigma.ToJSON()
	}

	for i, rp := range data.RegisteredRPs {
		if rp.TID == tid {
			data.RegisteredRPs[i].Domain = rpInfo.DomainCred.Domain
			data.RegisteredRPs[i].CallbackURL = rpInfo.CallbackURL
			data.RegisteredRPs[i].Scopes = rpInfo.Scopes
			data.RegisteredRPs[i].Sigma = sigmaBytes
			data.RegisteredRPs[i].RPDHPks = rpInfo.RPDHPks
			data.RegisteredRPs[i].Timestamp = time.Now().Format(time.RFC3339)
			exists = true
			break
		}
	}

	if !exists {
		data.RegisteredRPs = append(data.RegisteredRPs, BrokerRPInfo{
			TID:         tid,
			Domain:      rpInfo.DomainCred.Domain,
			CallbackURL: rpInfo.CallbackURL,
			Scopes:      rpInfo.Scopes,
			Sigma:       sigmaBytes,
			RPDHPks:     rpInfo.RPDHPks,
			Timestamp:   time.Now().Format(time.RFC3339),
		})
	}

	data.Timestamp = time.Now().Format(time.RFC3339)

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal registration data: %w", err)
	}
	if err := os.WriteFile(brokerRegDataFile(), jsonData, 0644); err != nil {
		return fmt.Errorf("write registration file: %w", err)
	}
	return nil
}

// loadRegistrationData reads the registration file, returning an empty record
// when it does not exist yet.
func (s *BrokerServer) loadRegistrationData() (*BrokerRegistrationData, error) {
	brokerRegistrationMutex.Lock()
	defer brokerRegistrationMutex.Unlock()

	data, err := os.ReadFile(brokerRegDataFile())
	if err != nil {
		if os.IsNotExist(err) {
			return &BrokerRegistrationData{RegisteredRPs: []BrokerRPInfo{}}, nil
		}
		return nil, fmt.Errorf("read registration file: %w", err)
	}

	var regData BrokerRegistrationData
	if err := json.Unmarshal(data, &regData); err != nil {
		return nil, fmt.Errorf("unmarshal registration data: %w", err)
	}
	return &regData, nil
}

// restoreRPIdentities rebuilds the in-memory RP table from persisted records,
// deserializing each DomainCredential signature.
func (s *BrokerServer) restoreRPIdentities(regData *BrokerRegistrationData) error {
	if s.store == nil {
		s.store = NewTempStorageService()
	}

	for _, rpInfo := range regData.RegisteredRPs {
		domainCred := &comm.DomainCredential{
			Domain: rpInfo.Domain,
			Sigma:  &lib.PSSignMsg{},
		}

		if len(rpInfo.Sigma) > 0 {
			if err := domainCred.Sigma.FromJSON(rpInfo.Sigma); err != nil {
				return fmt.Errorf("restore sigma for TID %s: %w", rpInfo.TID, err)
			}
		}

		s.store.rpIdentity[rpInfo.TID] = &rpIdentity{
			TID:         rpInfo.TID,
			DomainCred:  domainCred,
			CallbackURL: rpInfo.CallbackURL,
			Scopes:      rpInfo.Scopes,
			UserStore:   NewUserStore(),
			RPDHPks:     rpInfo.RPDHPks,
		}
	}
	return nil
}
