// IdP token helper: RSA signing keys and the minting and validation of ID,
// access and refresh tokens.
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

// TokenHelper signs and validates the IdP's JWTs.
type TokenHelper struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	Issuer    string
}

// IDTokenClaims are the id_token claims; Name and Email hold K_S ciphertext.
type IDTokenClaims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// AccessTokenClaims are the access_token claims; Scope holds K_S ciphertext.
type AccessTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// RefreshTokenClaims are the claims of a refresh token, which stays IdP-internal
// and therefore carries its values in the clear.
type RefreshTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// NewTokenHelper generates a fresh 2048-bit RSA signing key for the IdP.
func NewTokenHelper() *TokenHelper {
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

// GenerateIDToken signs an ID token. Its user-attribute fields are expected to
// arrive already encrypted under K_S; the envelope claims stay in the clear.
func (h *TokenHelper) GenerateIDToken(userID, name, email, audience string) (string, error) {
	claims := IDTokenClaims{
		Name:  name,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.Issuer,
			Subject:   userID,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
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

// GenerateAccessToken signs a 30-minute access token; sub and scope are expected
// to arrive already encrypted under K_S.
func (h *TokenHelper) GenerateAccessToken(userID, scope, audience string) (string, error) {
	claims := AccessTokenClaims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.Issuer,
			Subject:   userID,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
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

// GenerateRefreshToken signs a 2-hour refresh token, redeemable only through the
// broker relay back to this IdP.
func (h *TokenHelper) GenerateRefreshToken(userID, scope, audience string) (string, error) {
	claims := RefreshTokenClaims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.Issuer,
			Subject:   userID,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(120 * time.Minute)),
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

// rsaPublicKeyToJWK renders an RSA public key as a minimal JWK.
func rsaPublicKeyToJWK(pub *rsa.PublicKey) (map[string]interface{}, error) {
	nBytes := pub.N.Bytes()
	e := pub.E
	eBig := big.NewInt(int64(e))
	eBytes := eBig.Bytes()

	b64 := func(b []byte) string {
		return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	}

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

// ValidateRefreshToken verifies a refresh token and returns its claims.
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

// ValidateAccessToken verifies an access token and returns its claims.
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
