package broker

import (
	"encoding/json"
	"fmt"
	"os"
)

// ======================
// File paths (centralized)
// ======================

const (
	brokerConfigDir       = "Broker/config"
	brokerRuntimeConfFile = brokerConfigDir + "/config.json"
	brokerClientsFile     = brokerConfigDir + "/clients.json"
	brokerRPCredsFile     = brokerConfigDir + "/rp_credentials.json"
)

// ======================
// Runtime config
// ======================

type OIDCConfig struct {
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	JWKSURL      string
	RegisterURL  string
}

type IdPConfig struct {
	IdPURL       string
	IdPDockerURL string
}

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
	}
}

func (c *RuntimeConfig) Load(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(c)
}

func (c *RuntimeConfig) GetOIDCConfig() *OIDCConfig {
	conf := &OIDCConfig{
		// For browser access
		AuthorizeURL: c.IdPConfig.BrowserReachURL + c.IdPConfig.OIDCConfig.AuthorizePath,
		// For server-to-server access
		TokenURL:    c.IdPConfig.ServerReachURL + c.IdPConfig.OIDCConfig.TokenPath,
		UserInfoURL: c.IdPConfig.ServerReachURL + c.IdPConfig.OIDCConfig.UserInfoPath,
		JWKSURL:     c.IdPConfig.ServerReachURL + c.IdPConfig.OIDCConfig.JWKSPath,
		RegisterURL: c.IdPConfig.ServerReachURL + c.IdPConfig.OIDCConfig.RegisterPath,
	}
	return conf
}

// ======================
// Client storage (for RP clients registered with Broker)
// ======================

type BrokerClientStorage struct {
	Clients []BrokerClientData `json:"clients"`
}

type BrokerClientData struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name"`
}

func loadBrokerClients() (*BrokerClientStorage, error) {
	data, err := os.ReadFile(brokerClientsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &BrokerClientStorage{Clients: []BrokerClientData{}}, nil
		}
		return nil, fmt.Errorf("read clients file: %w", err)
	}

	var storage BrokerClientStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return nil, fmt.Errorf("unmarshal clients: %w", err)
	}

	return &storage, nil
}

func saveBrokerClients(clients map[string]*BrokerClient) error {
	storage := BrokerClientStorage{
		Clients: make([]BrokerClientData, 0, len(clients)),
	}

	for _, client := range clients {
		storage.Clients = append(storage.Clients, BrokerClientData{
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			RedirectURIs: client.RedirectURIs,
			Name:         client.Name,
		})
	}

	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal clients: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll(brokerConfigDir, 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	if err := os.WriteFile(brokerClientsFile, data, 0600); err != nil {
		return fmt.Errorf("write clients file: %w", err)
	}

	return nil
}

// ======================
// RP Credentials storage (for token refresh)
// ======================

type RPCredentialsStorage struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
}

func loadRPCredentials() (*RPCredentialsStorage, error) {
	data, err := os.ReadFile(brokerRPCredsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // 文件不存在，返回 nil
		}
		return nil, fmt.Errorf("read RP credentials file: %w", err)
	}

	var storage RPCredentialsStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return nil, fmt.Errorf("unmarshal RP credentials: %w", err)
	}

	return &storage, nil
}

func saveRPCredentials(creds *RPCredentials) error {
	if creds == nil {
		return nil // 没有凭据需要保存
	}

	storage := RPCredentialsStorage{
		ClientID:     creds.ClientID,
		ClientSecret: creds.ClientSecret,
		RedirectURI:  creds.RedirectURI,
	}

	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal RP credentials: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll(brokerConfigDir, 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	if err := os.WriteFile(brokerRPCredsFile, data, 0600); err != nil {
		return fmt.Errorf("write RP credentials file: %w", err)
	}

	return nil
}
