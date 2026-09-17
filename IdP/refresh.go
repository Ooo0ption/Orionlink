// IdP side of the token-refresh double ratchet: key derivation and the response
// to a broker-relayed refresh request.
package idp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"

	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/hkdf"
)

// RefreshTokenHelper holds the IdP's refresh-ratchet state and mints refreshed
// access tokens.
type RefreshTokenHelper struct {
	mu sync.Mutex

	rk     []byte
	ck     []byte
	seeded bool

	dhA *bls12381.G1

	isk *bls12381.Scalar
	ipk *bls12381.G1

	tokenHelper *TokenHelper
}

// refreshPayload is the plaintext the IdP encrypts under the ratcheted message
// key: the new access token and its lifetime.
type refreshPayload struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

// NewIdPRefreshTokenHelper creates the refresh helper with a fresh DH key pair;
// the root key is seeded from the persisted K_S on the first request.
func NewIdPRefreshTokenHelper(tokenHelper *TokenHelper) *RefreshTokenHelper {
	isk, ipk := lib.GenerateEmpKey()
	return &RefreshTokenHelper{
		isk:         isk,
		ipk:         ipk,
		tokenHelper: tokenHelper,
	}
}

// HandleBrokerRequest validates (hdr, seq, refresh_token), advances the ratchet,
// and returns the encrypted new access token as (hdr', seq, c).
func (h *RefreshTokenHelper) HandleBrokerRequest(req *protocol.RefreshTokenFromBrokerRequest) (*protocol.RefreshTokenToRPResponse, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	if len(req.Hdr) == 0 {
		return nil, errors.New("missing hdr")
	}
	if req.RefreshToken == "" {
		return nil, errors.New("missing refresh token")
	}
	if h.tokenHelper == nil {
		return nil, errors.New("tokenHelper not initialized")
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.seeded {
		h.rk = loadSessionKS()
		h.seeded = true
	}

	rpPk, err := comm.BytesToG1(req.Hdr)
	if err != nil || rpPk == nil {
		return nil, errors.New("invalid hdr bytes")
	}

	if h.dhA == nil || !h.dhA.IsEqual(rpPk) {
		h.dhA = rpPk
		h.isk, h.ipk = lib.GenerateEmpKey()
		dh, err := lib.DH(h.isk, h.dhA)
		if err != nil {
			return nil, err
		}
		h.rk, h.ck = kdfRK(h.rk, dh)
	}

	newCK, mk := kdfCK(h.ck)
	h.ck = newCK

	claims, err := h.tokenHelper.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, err
	}
	userID := claims.Subject
	scope := claims.Scope
	audience := ""
	if len(claims.Audience) > 0 {
		audience = claims.Audience[0]
	}
	accessToken, err := h.tokenHelper.GenerateAccessToken(userID, scope, audience)
	if err != nil {
		return nil, err
	}

	payload := refreshPayload{
		AccessToken: accessToken,
		ExpiresIn:   1800,
	}
	log.Printf("[INFO/IdP] Refresh: minted new access token, encrypted under a freshly ratcheted key (forward secrecy)")
	pt, _ := json.Marshal(payload)
	aad := refreshAAD(req.Seq, req.Hdr)
	ct, err := lib.AesGcmEncrypt(mk, pt, aad)
	if err != nil {
		return nil, err
	}

	return &protocol.RefreshTokenToRPResponse{
		Hdr: comm.G1ToBytes(h.ipk),
		Seq: req.Seq,
		C:   ct,
	}, nil
}

// refreshAAD binds a refresh ciphertext to its header and sequence number.
func refreshAAD(seq uint32, hdr []byte) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], seq)
	out := make([]byte, 0, len(hdr)+4)
	out = append(out, hdr...)
	out = append(out, b[:]...)
	return out
}

// kdfRK is the DH ratchet step: it mixes a new shared secret into the root key
// and derives the next root and chain keys.
func kdfRK(rk []byte, dh []byte) (newRK []byte, newCK []byte) {
	prk := hkdf.Extract(sha256.New, dh, rk)
	okm := make([]byte, 64)
	_, _ = io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("SecureSSO:Refresh:RKCK")), okm)
	return okm[:32], okm[32:]
}

// kdfCK is the symmetric ratchet step: it derives one message key and advances
// the chain key.
func kdfCK(ck []byte) (newCK []byte, mk []byte) {
	if len(ck) == 0 {
		ck = make([]byte, 32)
	}
	mkMac := hmac.New(sha256.New, ck)
	mkMac.Write([]byte("mk"))
	mk = mkMac.Sum(nil)

	ckMac := hmac.New(sha256.New, ck)
	ckMac.Write([]byte("ck"))
	newCK = ckMac.Sum(nil)
	return newCK, mk
}
