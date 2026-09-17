package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type TokenHelper struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	Issuer    string
}

type IDTokenClaims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type AccessTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

func NewTokenHelper() *TokenHelper {
	// Generate RSA keys for signing and verifying tokens
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}
	verifyKey := &signKey.PublicKey
	return &TokenHelper{
		signKey:   signKey,
		verifyKey: verifyKey,
	}
}

func (h *TokenHelper) GenerateIDToken(userID, name, audience string) (string, error) {
	claims := IDTokenClaims{
		Name: name,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.Issuer,
			Subject:   userID,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)), // 过期时间
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(h.signKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (h *TokenHelper) GenerateAccessToken(userID, scope, audience string) (string, error) {
	claims := AccessTokenClaims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.Issuer,
			Subject:   userID,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)), // 过期时间
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(h.signKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (h *TokenHelper) GenerateRefreshToken(userID, scope, audience string) (string, error) {
	claims := RefreshTokenClaims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.Issuer,
			Subject:   userID,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(120 * time.Minute)), // 过期时间
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(h.signKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

// rsaPublicKeyToJWK converts an *rsa.PublicKey to a minimal JWK representation.
func rsaPublicKeyToJWK(pub *rsa.PublicKey) (map[string]interface{}, error) {
	// n (modulus) and e (exponent) must be base64url-encoded
	// Convert modulus to big-endian bytes
	nBytes := pub.N.Bytes()
	e := pub.E
	// e as big.Int
	eBig := big.NewInt(int64(e))
	eBytes := eBig.Bytes()

	// base64url without padding
	b64 := func(b []byte) string {
		return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	}

	// Compute kid as sha256 of modulus|exponent, base64url
	h := sha256.New()
	h.Write(nBytes)
	h.Write(eBytes)
	kid := strings.TrimRight(base64.URLEncoding.EncodeToString(h.Sum(nil)), "=")

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   b64(nBytes),
		"e":   b64(eBytes),
	}
	return jwk, nil
}

// ValidateRefreshToken 验证refresh token并返回claims
func (h *TokenHelper) ValidateRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return h.verifyKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*RefreshTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrInvalidKey
}

// ValidateAccessToken 验证access token并返回claims
func (h *TokenHelper) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return h.verifyKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AccessTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrInvalidKey
}
