// IdP persistence: on-disk identity and credential keys, plus the AAKA session
// key used to seed the refresh ratchet.
package idp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// Runtime file locations, resolved through internal/config.
func idpConfigDir() string      { return orionconf.Get().RoleConfigDir("IdP") }
func idpKeyStorageFile() string { return orionconf.Get().RoleConfigPath("IdP", "key_storage.json") }
func idpUsersFile() string      { return orionconf.Get().RoleConfigPath("IdP", "users.json") }

// KeyStorage is the layout of the IdP's key_storage.json.
type KeyStorage struct {
	IdentityKey *IdentityKeyData `json:"identity_key,omitempty"`
	CredKey     *CredKeyData     `json:"cred_key,omitempty"`
	SessionKS   *SessionKSData   `json:"session_ks,omitempty"`
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
	storage, err := loadKeyStorage()
	if err != nil {
		storage = &KeyStorage{}
	}
	storage.SessionKS = &SessionKSData{KSHex: hex.EncodeToString(ks)}
	return saveKeyStorage(storage)
}

// loadSessionKS reads the persisted K_S, falling back to the shared bootstrap
// value when no session has been persisted.
func loadSessionKS() []byte {
	storage, err := loadKeyStorage()
	if err != nil || storage.SessionKS == nil || storage.SessionKS.KSHex == "" {
		return append([]byte(nil), comm.BootstrapRefreshKS...)
	}
	ks, err := hex.DecodeString(storage.SessionKS.KSHex)
	if err != nil || len(ks) == 0 {
		return append([]byte(nil), comm.BootstrapRefreshKS...)
	}
	return ks
}

// IdentityKeyData is the persisted AAKA identity key pair, hex-encoded.
type IdentityKeyData struct {
	SKHex string `json:"sk_hex"`
	PKHex string `json:"pk_hex"`
}

// CredKeyData is the persisted PS credential key material: the x and y_n secret
// scalars of both PS key pairs, hex-encoded.
type CredKeyData struct {
	PSKey1XHex  string   `json:"ps_key1_x_hex"`
	PSKey1YnHex []string `json:"ps_key1_yn_hex"`
	PSKey2XHex  string   `json:"ps_key2_x_hex"`
	PSKey2YnHex []string `json:"ps_key2_yn_hex"`
}

// loadKeyStorage reads the persisted key material.
func loadKeyStorage() (*KeyStorage, error) {
	paths := []string{idpKeyStorageFile(), filepath.Join(orionconf.Get().DataDir, "IdP", "key_storage.json")}
	var lastErr error
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		var storage KeyStorage
		if err := json.Unmarshal(data, &storage); err != nil {
			return nil, fmt.Errorf("unmarshal key storage (%s): %w", p, err)
		}
		return &storage, nil
	}
	if lastErr != nil && os.IsNotExist(lastErr) {
		return &KeyStorage{}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("key storage not found")
	}
	return nil, fmt.Errorf("read key storage file: %w", lastErr)
}

// saveKeyStorage writes the key material back to disk with 0600 permissions.
func saveKeyStorage(storage *KeyStorage) error {
	jsonData, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key storage: %w", err)
	}
	if err := os.WriteFile(idpKeyStorageFile(), jsonData, 0600); err != nil {
		return fmt.Errorf("write key storage file: %w", err)
	}
	return nil
}

// loadIdentityKey restores the AAKA identity key pair from key storage.
func loadIdentityKey() (lib.DHKey, error) {
	storage, err := loadKeyStorage()
	if err != nil {
		return lib.DHKey{}, err
	}
	if storage.IdentityKey == nil || storage.IdentityKey.SKHex == "" || storage.IdentityKey.PKHex == "" {
		return lib.DHKey{}, fmt.Errorf("identity key not found in storage")
	}
	skBytes, err := hex.DecodeString(storage.IdentityKey.SKHex)
	if err != nil {
		return lib.DHKey{}, fmt.Errorf("decode SK hex: %w", err)
	}
	pkBytes, err := hex.DecodeString(storage.IdentityKey.PKHex)
	if err != nil {
		return lib.DHKey{}, fmt.Errorf("decode PK hex: %w", err)
	}
	sk, err := comm.BytesToScalar(skBytes)
	if err != nil {
		return lib.DHKey{}, fmt.Errorf("convert SK to scalar: %w", err)
	}
	pk, err := comm.BytesToG1(pkBytes)
	if err != nil {
		return lib.DHKey{}, fmt.Errorf("convert PK to G1: %w", err)
	}
	return lib.DHKey{SK: sk, PK: pk}, nil
}

// saveIdentityKey persists the AAKA identity key pair.
func saveIdentityKey(key lib.DHKey) error {
	storage, err := loadKeyStorage()
	if err != nil {
		storage = &KeyStorage{}
	}
	skBytes := comm.ScalarToBytes(key.SK)
	pkBytes := comm.G1ToBytes(key.PK)
	storage.IdentityKey = &IdentityKeyData{
		SKHex: hex.EncodeToString(skBytes),
		PKHex: hex.EncodeToString(pkBytes),
	}
	return saveKeyStorage(storage)
}

// loadCredKey rebuilds both PS credential key pairs from the persisted secret
// scalars, recomputing the public keys from them.
func loadCredKey() (*comm.ServerCredKey, error) {
	storage, err := loadKeyStorage()
	if err != nil {
		return nil, err
	}
	if storage.CredKey == nil || storage.CredKey.PSKey1XHex == "" || storage.CredKey.PSKey2XHex == "" {
		return nil, fmt.Errorf("cred key not found in storage")
	}

	credKey := &comm.ServerCredKey{}

	psKey1 := &lib.PSKey{SecretKey: &lib.PSSecretKey{}, PublicKey: &lib.PSPublicKey{}}
	x1Bytes, err := hex.DecodeString(storage.CredKey.PSKey1XHex)
	if err != nil {
		return nil, fmt.Errorf("decode PSKey1 x hex: %w", err)
	}
	x1, err := comm.BytesToScalar(x1Bytes)
	if err != nil {
		return nil, fmt.Errorf("set PSKey1 x: %w", err)
	}
	psKey1.SecretKey.SetSecretX(x1)
	psKey1.PublicKey.Xhat = new(bls12381.G2)
	psKey1.PublicKey.Xhat.ScalarMult(x1, bls12381.G2Generator())

	yn1 := make([]*bls12381.Scalar, len(storage.CredKey.PSKey1YnHex))
	for i, ynHex := range storage.CredKey.PSKey1YnHex {
		ynBytes, err := hex.DecodeString(ynHex)
		if err != nil {
			return nil, fmt.Errorf("decode PSKey1 yn[%d] hex: %w", i, err)
		}
		yn1[i], err = comm.BytesToScalar(ynBytes)
		if err != nil {
			return nil, fmt.Errorf("set PSKey1 yn[%d]: %w", i, err)
		}
	}
	psKey1.SecretKey.SetSecretY(yn1, psKey1.PublicKey)
	credKey.PSKey1 = psKey1

	psKey2 := &lib.PSKey{SecretKey: &lib.PSSecretKey{}, PublicKey: &lib.PSPublicKey{}}
	x2Bytes, err := hex.DecodeString(storage.CredKey.PSKey2XHex)
	if err != nil {
		return nil, fmt.Errorf("decode PSKey2 x hex: %w", err)
	}
	x2, err := comm.BytesToScalar(x2Bytes)
	if err != nil {
		return nil, fmt.Errorf("set PSKey2 x: %w", err)
	}
	psKey2.SecretKey.SetSecretX(x2)
	psKey2.PublicKey.Xhat = new(bls12381.G2)
	psKey2.PublicKey.Xhat.ScalarMult(x2, bls12381.G2Generator())

	yn2 := make([]*bls12381.Scalar, len(storage.CredKey.PSKey2YnHex))
	for i, ynHex := range storage.CredKey.PSKey2YnHex {
		ynBytes, err := hex.DecodeString(ynHex)
		if err != nil {
			return nil, fmt.Errorf("decode PSKey2 yn[%d] hex: %w", i, err)
		}
		yn2[i], err = comm.BytesToScalar(ynBytes)
		if err != nil {
			return nil, fmt.Errorf("set PSKey2 yn[%d]: %w", i, err)
		}
	}
	psKey2.SecretKey.SetSecretY(yn2, psKey2.PublicKey)
	credKey.PSKey2 = psKey2

	return credKey, nil
}

// saveCredKey persists the secret scalars of both PS credential key pairs.
func saveCredKey(credKey *comm.ServerCredKey) error {
	storage, err := loadKeyStorage()
	if err != nil {
		storage = &KeyStorage{}
	}

	credKeyData := &CredKeyData{}

	if credKey.PSKey1 != nil && credKey.PSKey1.SecretKey != nil {
		x1 := credKey.PSKey1.SecretKey.GetSecretX()
		if x1 != nil {
			credKeyData.PSKey1XHex = hex.EncodeToString(comm.ScalarToBytes(x1))
		}
		yn1 := credKey.PSKey1.SecretKey.GetSecretY()
		credKeyData.PSKey1YnHex = make([]string, len(yn1))
		for i, y := range yn1 {
			if y != nil {
				credKeyData.PSKey1YnHex[i] = hex.EncodeToString(comm.ScalarToBytes(y))
			}
		}
	}

	if credKey.PSKey2 != nil && credKey.PSKey2.SecretKey != nil {
		x2 := credKey.PSKey2.SecretKey.GetSecretX()
		if x2 != nil {
			credKeyData.PSKey2XHex = hex.EncodeToString(comm.ScalarToBytes(x2))
		}
		yn2 := credKey.PSKey2.SecretKey.GetSecretY()
		credKeyData.PSKey2YnHex = make([]string, len(yn2))
		for i, y := range yn2 {
			if y != nil {
				credKeyData.PSKey2YnHex[i] = hex.EncodeToString(comm.ScalarToBytes(y))
			}
		}
	}

	storage.CredKey = credKeyData
	return saveKeyStorage(storage)
}
