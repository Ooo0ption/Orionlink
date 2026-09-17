// Broker token handling: JWT minting under the broker key, JWKS retrieval, and
// re-signing of the tokens received from the IdP.
package broker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// TokenHelper signs and verifies the broker's own JWTs.
type TokenHelper struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	Issuer    string
}

// IDTokenClaims are the id_token claims re-signed by the broker. Name and Email
// stay in their K_S-encrypted form; the broker never sees the plaintext.
type IDTokenClaims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// AccessTokenClaims are the access_token claims re-signed by the broker.
type AccessTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// RefreshTokenClaims are the claims of a broker-issued refresh token.
type RefreshTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// NewTokenHelper generates a fresh 2048-bit RSA signing key for the broker.
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

// GenerateIDToken mints a 5-minute id_token signed with the broker key.
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

// GenerateAccessToken mints a 30-minute access_token signed with the broker key.
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

// GenerateRefreshToken mints a 2-hour refresh token signed with the broker key.
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

// fetchJWKS retrieves the JWKS document from the configured IdP endpoint.
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

// jwkToPublicKey parses one RSA JWK into an *rsa.PublicKey.
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
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
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
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	pub := &rsa.PublicKey{N: n, E: e}
	return pub, nil
}

// VerifyIDToken validates an id_token against the IdP's JWKS and returns its claims.
func (t *TokenHelper) VerifyIDToken(jwtPubKeyEndpoint string, tokenString string) (map[string]interface{}, error) {
	parser := new(jwt.Parser)
	unverifiedToken, parts, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	hdr := unverifiedToken.Header
	kid, _ := hdr["kid"].(string)
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

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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
		out := make(map[string]interface{})
		for k, v := range claims {
			out[k] = v
		}
		_ = parts
		return out, nil
	}
	return nil, fmt.Errorf("failed to extract claims")
}

// resignTokensWithBrokerKey re-signs the IdP's tokens under the broker's own key,
// leaving the encrypted claims untouched.
func (t *TokenHelper) resignTokensWithBrokerKey(jwtPubKeyEndpoint string, originalTokens *Tokens) (*Tokens, error) {
	reSignedTokens := &Tokens{
		TokenType: originalTokens.TokenType,
	}

	if originalTokens.AccessToken != "" {
		claims, err := t.VerifyIDToken(jwtPubKeyEndpoint, originalTokens.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to extract claims from token: %v", err)
		}
		auds := claims["aud"].([]interface{})
		var aud string
		if len(auds) > 0 {
			aud = auds[0].(string)
		} else {
			aud = ""
		}
		reSignedAccessToken, _ := t.GenerateAccessToken(claims["sub"].(string), claims["scope"].(string), aud)
		reSignedTokens.AccessToken = reSignedAccessToken
		log.Printf("[INFO/Broker] Access token re-signed with broker's private key")
	}

	if originalTokens.IDToken != "" {
		claims, err := t.VerifyIDToken(jwtPubKeyEndpoint, originalTokens.IDToken)
		if err != nil {
			return nil, fmt.Errorf("failed to extract claims from token: %v", err)
		}
		auds := claims["aud"].([]interface{})
		var aud string
		if len(auds) > 0 {
			aud = auds[0].(string)
		} else {
			aud = ""
		}
		reSignedIDToken, _ := t.GenerateIDToken(claims["sub"].(string), claims["name"].(string), claims["email"].(string), aud)
		reSignedTokens.IDToken = reSignedIDToken
		log.Printf("[INFO/Broker] ID token re-signed with broker's private key")
	}

	reSignedTokens.RefreshToken = originalTokens.RefreshToken

	return reSignedTokens, nil
}
