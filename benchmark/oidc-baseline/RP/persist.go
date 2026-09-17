package rp

import (
	"encoding/json"
	"os"
)

// ======================
// File paths (centralized)
// ======================

const (
	rpConfigDir       = "RP/config"
	rpRuntimeConfFile = rpConfigDir + "/config.json"
)

// ======================
// Runtime config (config.go)
// ======================

type OIDCConfig struct {
	AuthorizeURL      string
	TokenURL          string
	UserInfoURL       string
	JWKSURL           string
	IdPRegisterURL    string
	BrokerRegisterURL string
	RedirectURI       string
}

type IdPConfig struct {
	IdPURL       string
	IdPDockerURL string
}

type RuntimeConfig struct {
	Port            string
	OIDCRedirectURI string
	IdPConfig       struct {
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
		AuthorizeURL: c.BrokerConfig.BrowserReachURL + c.BrokerConfig.OIDCConfig.AuthorizePath,
		// For server-to-server access
		TokenURL:          c.BrokerConfig.ServerReachURL + c.BrokerConfig.OIDCConfig.TokenPath,
		UserInfoURL:       c.BrokerConfig.ServerReachURL + c.BrokerConfig.OIDCConfig.UserInfoPath,
		JWKSURL:           c.BrokerConfig.ServerReachURL + c.BrokerConfig.OIDCConfig.JWKSPath,
		BrokerRegisterURL: c.BrokerConfig.ServerReachURL + c.BrokerConfig.OIDCConfig.RegisterPath,
		IdPRegisterURL:    c.IdPConfig.ServerReachURL + c.IdPConfig.OIDCConfig.RegisterPath,
		RedirectURI:       c.OIDCRedirectURI,
	}
	return conf
}
