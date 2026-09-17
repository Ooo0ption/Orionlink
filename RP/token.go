// RP token verification: JWK parsing and id_token validation against the IdP's JWKS.
package rp

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v4"
)

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
func (s *RPServer) VerifyIDToken(tokenString string) (map[string]interface{}, error) {
	parser := new(jwt.Parser)
	unverifiedToken, parts, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	hdr := unverifiedToken.Header
	kid, _ := hdr["kid"].(string)
	jwks, err := s.fetchJWKS()
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
