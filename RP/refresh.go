// RP side of the token-refresh double ratchet: precomputed DH key pairs and
// decryption of the refreshed token.
package rp

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

// RefreshTokenHelper holds the RP's refresh-ratchet state: the precomputed DH
// key pairs whose public halves the broker stores, plus the root and chain keys.
type RefreshTokenHelper struct {
	mu sync.Mutex

	rsk []*bls12381.Scalar
	rpk []*bls12381.G1

	rk     []byte
	ck     []byte
	seeded bool
	dhB    *bls12381.G1
}

// refreshPayload is the plaintext the IdP encrypts under the ratcheted message
// key: the new access token and its lifetime.
type refreshPayload struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

// NewRefreshTokenHelper restores up to precomputeN persisted refresh DH keys and
// tops the pool up to exactly precomputeN pairs, persisting any it had to generate.
func NewRefreshTokenHelper(precomputeN int) *RefreshTokenHelper {
	if precomputeN <= 0 {
		precomputeN = 64
	}
	h := &RefreshTokenHelper{}

	persisted := loadRefreshKeys()
	restoreCount := min(len(persisted), precomputeN)
	for _, sk := range persisted[:restoreCount] {
		pk := new(bls12381.G1)
		pk.ScalarMult(sk, bls12381.G1Generator())
		h.rsk = append(h.rsk, sk)
		h.rpk = append(h.rpk, pk)
	}

	if grew := len(h.rsk) < precomputeN; grew {
		for i := len(h.rsk); i < precomputeN; i++ {
			sk, pk := lib.GenerateEmpKey()
			h.rsk = append(h.rsk, sk)
			h.rpk = append(h.rpk, pk)
		}
		if err := saveRefreshKeys(h.rsk); err != nil {
			log.Printf("[WARN/RP] failed to persist refresh DH keys: %v", err)
		}
		if len(persisted) > 0 {
			log.Printf("[INFO/RP] refresh DH key pool grown %d -> %d; register with the broker again for it to take effect",
				len(persisted), len(h.rsk))
		}
	}
	return h
}

// PublicKeys returns the compressed bytes of every precomputed refresh DH public key.
func (h *RefreshTokenHelper) PublicKeys() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([][]byte, 0, len(h.rpk))
	for _, pk := range h.rpk {
		out = append(out, comm.G1ToBytes(pk))
	}
	return out
}

// DecryptResponse derives the message key from a relayed (hdr, seq, c) response
// and returns the new access token.
func (h *RefreshTokenHelper) DecryptResponse(resp *protocol.RefreshTokenToRPResponse) (string, error) {
	if resp == nil {
		return "", errors.New("nil refresh response")
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.seeded {
		h.rk = loadSessionKS()
		h.seeded = true
	}

	if int(resp.Seq) < 0 || int(resp.Seq) >= len(h.rsk) {
		return "", errors.New("seq out of range")
	}
	peerPk, err := comm.BytesToG1(resp.Hdr)
	if err != nil || peerPk == nil {
		return "", errors.New("invalid hdr")
	}

	if h.dhB == nil || !h.dhB.IsEqual(peerPk) {
		h.dhB = peerPk
		dh, err := lib.DH(h.rsk[resp.Seq], peerPk)
		if err != nil {
			return "", err
		}
		h.rk, h.ck = kdfRK(h.rk, dh)
	}

	newCK, mk := kdfCK(h.ck)
	h.ck = newCK

	rpHdr := comm.G1ToBytes(h.rpk[resp.Seq])
	aad := refreshAAD(resp.Seq, rpHdr)
	pt, err := lib.AesGcmDecrypt(mk, resp.C, aad)
	if err != nil {
		return "", err
	}
	var payload refreshPayload
	if err := json.Unmarshal(pt, &payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("empty access_token in payload")
	}
	log.Printf("[INFO/RP] Refresh: decrypted new access token from the ratcheted response (broker never saw it)")
	return payload.AccessToken, nil
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
