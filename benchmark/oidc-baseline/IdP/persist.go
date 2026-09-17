package idp

import (
	"encoding/json"
	"fmt"
	"os"
)

// ======================
// File paths (centralized)
// ======================

const (
	idpConfigDir      = "IdP/config"
	idpUsersFile      = idpConfigDir + "/users.json"
	idpClientsFile    = idpConfigDir + "/clients.json"
)

// ======================
// Client storage (for OIDC clients: RP and Broker)
// ======================

type ClientStorage struct {
	Clients []ClientData `json:"clients"`
}

type ClientData struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name"`
	ClientType   string   `json:"client_type"` // "broker" or "rp"
}

func loadClients() (*ClientStorage, error) {
	data, err := os.ReadFile(idpClientsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &ClientStorage{Clients: []ClientData{}}, nil
		}
		return nil, fmt.Errorf("read clients file: %w", err)
	}

	var storage ClientStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return nil, fmt.Errorf("unmarshal clients: %w", err)
	}

	return &storage, nil
}

func saveClients(clients map[string]*Client) error {
	storage := ClientStorage{
		Clients: make([]ClientData, 0, len(clients)),
	}

	for _, client := range clients {
		// 使用客户端保存的 ClientType，如果没有则通过名称推断
		clientType := client.ClientType
		if clientType == "" {
			// 向后兼容：如果没有保存类型，通过名称推断
			if client.Name == "OIDC Broker" || client.Name == "Broker" {
				clientType = "broker"
			} else {
				clientType = "rp"
			}
		}

		storage.Clients = append(storage.Clients, ClientData{
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			RedirectURIs: client.RedirectURIs,
			Name:         client.Name,
			ClientType:   clientType,
		})
	}

	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal clients: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll(idpConfigDir, 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	if err := os.WriteFile(idpClientsFile, data, 0600); err != nil {
		return fmt.Errorf("write clients file: %w", err)
	}

	return nil
}
