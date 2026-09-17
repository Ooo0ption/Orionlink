// Package oprf holds the server side of the Ristretto255 PIN-OPRF the IdP
// evaluates during the consent flow. The client side (Blind / Unblind) runs in
// the browser inside the TCA iframe, in tca/cryptolib.js.
package oprf

import (
	"crypto/rand"

	"github.com/cloudflare/circl/group"
)

// PinHelper holds the OPRF key the IdP evaluates PIN-derived blinded points with.
type PinHelper struct {
	Group group.Group
	Skey  group.Scalar
}

// NewPinHelper constructs a PinHelper with a freshly generated server key.
func NewPinHelper() *PinHelper {
	out := &PinHelper{Group: group.Ristretto255}
	out.GenSecretKey()
	return out
}

// GenSecretKey draws a fresh non-zero server OPRF key uniformly from the full
// Ristretto255 scalar field.
func (h *PinHelper) GenSecretKey() {
	h.Skey = h.Group.RandomNonZeroScalar(rand.Reader)
}

// ServerEvaluate multiplies a blinded client point by the server key and returns
// the serialized result for the client to unblind.
func (h *PinHelper) ServerEvaluate(blinded []byte) ([]byte, error) {
	P := h.Group.NewElement()
	if err := P.UnmarshalBinary(blinded); err != nil {
		return nil, err
	}
	P.Mul(P, h.Skey)
	return P.MarshalBinary()
}
