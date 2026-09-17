package broker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
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

func (h *TokenHelper) GenerateIDToken(userID, name, email, audience string) (string, error) {
	claims := IDTokenClaims{
		Name:  name,
		Email: email,
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

// fetchJWKS fetches jwks JSON from the configured idp jwks endpoint
func fetchJWKS(jwtPubKeyEndpoint string) (map[string]interface{}, error) {
	resp, err := http.Get(jwtPubKeyEndpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	var jwks map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	return jwks, nil
}

// jwkToPublicKey converts a single JWK (map) to *rsa.PublicKey. Expects kty=RSA and n,e fields.
func jwkToPublicKey(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	if kty != "RSA" {
		return nil, fmt.Errorf("unsupported kty: %s", kty)
	}
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	if nStr == "" || eStr == "" {
		return nil, fmt.Errorf("missing n or e in jwk")
	}
	// base64url decode
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		// try standard URLEncoding without Raw
		nBytes, err = base64.URLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, err
		}
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		eBytes, err = base64.URLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, err
		}
	}
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	// convert eBytes to int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	pub := &rsa.PublicKey{N: n, E: e}
	return pub, nil
}

// VerifyIDToken verifies the id_token using the IdP's JWKS and returns the claims as map
func (t *TokenHelper) VerifyIDToken(jwtPubKeyEndpoint string, tokenString string) (map[string]interface{}, error) {
	// parse token to extract header and kid
	parser := new(jwt.Parser)
	unverifiedToken, parts, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	hdr := unverifiedToken.Header
	kid, _ := hdr["kid"].(string)
	// fetch JWKS (from .well-known/jwks.json). Here s.config.pubKeyEndpoint expected to be jwks endpoint
	jwks, err := fetchJWKS(jwtPubKeyEndpoint)
	if err != nil {
		return nil, err
	}
	keys, _ := jwks["keys"].([]interface{})
	var pub *rsa.PublicKey
	for _, k := range keys {
		if km, ok := k.(map[string]interface{}); ok {
			if kid != "" {
				if km["kid"] == kid {
					pub, err = jwkToPublicKey(km)
					if err != nil {
						return nil, err
					}
					break
				}
			} else {
				// if no kid provided, just take the first RSA key
				if km["kty"] == "RSA" {
					pub, err = jwkToPublicKey(km)
					if err != nil {
						return nil, err
					}
					break
				}
			}
		}
	}
	if pub == nil {
		return nil, fmt.Errorf("no matching public key found in jwks (kid=%s)", kid)
	}

	// now finally parse and verify the token using the public key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// check alg
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pub, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("token invalid")
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// convert to plain map[string]interface{}
		out := make(map[string]interface{})
		for k, v := range claims {
			out[k] = v
		}
		// ensure parts unused variable to avoid lint warning
		_ = parts
		return out, nil
	}
	return nil, fmt.Errorf("failed to extract claims")
}
