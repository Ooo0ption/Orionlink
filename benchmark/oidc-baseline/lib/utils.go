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

type DHKey struct {
	SK *bls12381.Scalar
	PK *bls12381.G1
}

// 生成16字节的随机数
func NewRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// 生成临时公私钥对
func GenerateEmpKey() (*bls12381.Scalar, *bls12381.G1) {
	sk := new(bls12381.Scalar)
	pk := new(bls12381.G1)
	if err := sk.Random(rand.Reader); err != nil {
		panic(err)
	}
	pk.ScalarMult(sk, bls12381.G1Generator())
	return sk, pk
}

// 计算单个DH配对的结果
func DH(sk *bls12381.Scalar, pk *bls12381.G1) ([]byte, error) {
	if sk == nil || pk == nil {
		return nil, errors.New("sk or pk is nil")
	}
	var S bls12381.G1
	S.ScalarMult(sk, pk)

	dh := S.BytesCompressed()
	return dh, nil
}

// 计算3DH交互的结果
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

// 派生Session_key的函数，Client和Server都要调用
func DeriveSessionKey(dh1 []byte, dh2 []byte, dh3 []byte) (sessionKey []byte, err error) {
	// 1. compute the exchange result
	ikm := append(dh1, append(dh2, dh3...)...)

	// 2. Derive session_key
	prk := hkdf.Extract(sha256.New, ikm, nil)
	sessionKey = deriveSecret(prk, "SessionKey", nil, 32)

	return sessionKey, nil
}

func deriveSecret(secret []byte, label string, context []byte, length int) []byte {
	// 构造HKDF info字段
	info := append([]byte(label+":"), context...)

	// Expand阶段
	hkdfReader := hkdf.Expand(sha256.New, secret, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdfReader, out); err != nil {
		panic(err)
	}
	return out
}

func ComputeMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// AES-GCM helper: encrypt with AES-256-GCM. Returns nonce||ciphertext where nonce length = gcm.NonceSize().
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

// AES-GCM helper: decrypt a buffer produced by AesGcmEncrypt (nonce||ciphertext).
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
func HashStringToScalar(msg string) *bls12381.Scalar {
	sum := sha256.Sum256([]byte(msg))
	var s bls12381.Scalar
	s.SetBytes(sum[:])
	return &s
}
func AESEncryptString(key []byte, plaintext string) (string, error) {
	plaintextBytes := []byte(plaintext)

	ciphertext, err := AesGcmEncrypt(key, plaintextBytes, nil)
	if err != nil {
		return "", err
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextB64, nil
}

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
