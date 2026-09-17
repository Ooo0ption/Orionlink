package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	"github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/hkdf"
)

// DHKey is a Diffie-Hellman key pair on BLS12-381.
type DHKey struct {
	SK *bls12381.Scalar
	PK *bls12381.G1
}

// NewRandomID returns a 16-byte random identifier in hex.
func NewRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateEmpKey creates an ephemeral BLS12-381 key pair.
func GenerateEmpKey() (*bls12381.Scalar, *bls12381.G1) {
	sk := new(bls12381.Scalar)
	pk := new(bls12381.G1)
	if err := sk.Random(rand.Reader); err != nil {
		panic(err)
	}
	pk.ScalarMult(sk, bls12381.G1Generator())
	return sk, pk
}

// DH computes a single Diffie-Hellman shared point and returns it compressed.
func DH(sk *bls12381.Scalar, pk *bls12381.G1) ([]byte, error) {
	if sk == nil || pk == nil {
		return nil, errors.New("sk or pk is nil")
	}
	var S bls12381.G1
	S.ScalarMult(sk, pk)

	dh := S.BytesCompressed()
	return dh, nil
}

// X3KeyExchange runs the three Diffie-Hellman pairings of the X3DH handshake.
func X3KeyExchange(sk1 *bls12381.Scalar, sk2 *bls12381.Scalar, pk1 *bls12381.G1, pk2 *bls12381.G1) (dh1, dh2, dh3 []byte, err error) {
	if sk1 == nil || pk1 == nil || sk2 == nil || pk2 == nil {
		return nil, nil, nil, errors.New("sk or pk is nil")
	}
	dh1, err = DH(sk1, pk2)
	if err != nil {
		return nil, nil, nil, err
	}
	dh2, err = DH(sk2, pk1)
	if err != nil {
		return nil, nil, nil, err
	}
	dh3, err = DH(sk2, pk2)
	if err != nil {
		return nil, nil, nil, err
	}

	return dh1, dh2, dh3, nil
}

// DeriveSessionKey derives the shared session key K_S from the three X3DH outputs.
// Both sides run it on the same inputs.
func DeriveSessionKey(dh1 []byte, dh2 []byte, dh3 []byte) (sessionKey []byte, err error) {
	ikm := append(dh1, append(dh2, dh3...)...)

	prk := hkdf.Extract(sha256.New, ikm, nil)
	sessionKey = deriveSecret(prk, "SessionKey", nil, 32)

	return sessionKey, nil
}

// deriveSecret expands a PRK into a labelled key of the requested length.
func deriveSecret(secret []byte, label string, context []byte, length int) []byte {
	info := append([]byte(label+":"), context...)

	hkdfReader := hkdf.Expand(sha256.New, secret, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdfReader, out); err != nil {
		panic(err)
	}
	return out
}

// ComputeMAC returns the HMAC-SHA256 tag of data under key.
func ComputeMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// AesGcmEncrypt seals plaintext with AES-256-GCM and returns nonce||ciphertext.
func AesGcmEncrypt(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key length must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// AesGcmDecrypt opens a buffer produced by AesGcmEncrypt.
func AesGcmDecrypt(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key length must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// HashStringToScalar maps a string onto a BLS12-381 scalar via SHA-256.
func HashStringToScalar(msg string) *bls12381.Scalar {
	sum := sha256.Sum256([]byte(msg))
	var s bls12381.Scalar
	s.SetBytes(sum[:])
	return &s
}

// AESEncryptString encrypts a string and returns base64-encoded ciphertext.
func AESEncryptString(key []byte, plaintext string) (string, error) {
	plaintextBytes := []byte(plaintext)

	ciphertext, err := AesGcmEncrypt(key, plaintextBytes, nil)
	if err != nil {
		return "", err
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextB64, nil
}

// AESDecryptString reverses AESEncryptString.
func AESDecryptString(key []byte, ciphertextB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	plaintext, err := AesGcmDecrypt(key, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
