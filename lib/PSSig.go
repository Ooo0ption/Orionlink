// Package lib holds OrionLink's cryptographic primitives over BLS12-381.
//
// This file implements the Pointcheval-Sanders signature scheme: key generation,
// signing, verification, and signature randomization.
package lib

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// PSSignMsg is a PS signature: a pair of G1 elements.
type PSSignMsg struct {
	Sigma1 *bls12381.G1
	Sigma2 *bls12381.G1
}

// PSSecretKey holds the signing secrets: x, one y per attribute, and X = g1^x.
type PSSecretKey struct {
	x  *bls12381.Scalar
	yn []*bls12381.Scalar
	X  *bls12381.G1
}

// GetSecretY returns the per-attribute secret scalar vector.
func (sk *PSSecretKey) GetSecretY() []*bls12381.Scalar {
	return sk.yn
}

// GetSecretX returns the secret scalar x.
func (sk *PSSecretKey) GetSecretX() *bls12381.Scalar {
	return sk.x
}

// SetSecretX overrides x and recomputes the matching public component X.
func (sk *PSSecretKey) SetSecretX(x *bls12381.Scalar) {
	sk.x = x
	if sk.X == nil {
		sk.X = new(bls12381.G1)
	}
	sk.X.ScalarMult(x, bls12381.G1Generator())
}

// SetSecretY overrides the per-attribute secrets and, when a public key is given,
// recomputes the matching Yn and Yhatn components.
func (sk *PSSecretKey) SetSecretY(yn []*bls12381.Scalar, publicKey *PSPublicKey) {
	sk.yn = yn
	if publicKey != nil {
		if len(publicKey.Yn) != len(yn) {
			publicKey.Yn = make([]*bls12381.G1, len(yn))
			publicKey.Yhatn = make([]*bls12381.G2, len(yn))
		}
		for i, y := range yn {
			if publicKey.Yn[i] == nil {
				publicKey.Yn[i] = new(bls12381.G1)
			}
			publicKey.Yn[i].ScalarMult(y, bls12381.G1Generator())
			if publicKey.Yhatn[i] == nil {
				publicKey.Yhatn[i] = new(bls12381.G2)
			}
			publicKey.Yhatn[i].ScalarMult(y, bls12381.G2Generator())
		}
	}
}

// PSPublicKey holds the verification components: Xhat = g2^x plus per-attribute Yn and Yhatn.
type PSPublicKey struct {
	Yn    []*bls12381.G1
	Xhat  *bls12381.G2
	Yhatn []*bls12381.G2
}

// PSKey pairs a PS secret key with its public key.
type PSKey struct {
	SecretKey *PSSecretKey
	PublicKey *PSPublicKey
}

// PSKeyGen generates a PS key pair supporting up to n signed attributes.
func PSKeyGen(n int) *PSKey {
	var key PSKey
	key.SecretKey = &PSSecretKey{}
	key.PublicKey = &PSPublicKey{}

	key.SecretKey.x = new(bls12381.Scalar)
	if err := key.SecretKey.x.Random(rand.Reader); err != nil {
		panic(err)
	}
	key.SecretKey.X = new(bls12381.G1)
	key.SecretKey.X.ScalarMult(key.SecretKey.x, bls12381.G1Generator())
	key.PublicKey.Xhat = new(bls12381.G2)
	key.PublicKey.Xhat.ScalarMult(key.SecretKey.x, bls12381.G2Generator())

	key.SecretKey.yn = make([]*bls12381.Scalar, n)
	key.PublicKey.Yn = make([]*bls12381.G1, n)
	key.PublicKey.Yhatn = make([]*bls12381.G2, n)

	for i := 0; i < n; i++ {
		key.SecretKey.yn[i] = new(bls12381.Scalar)
		if err := key.SecretKey.yn[i].Random(rand.Reader); err != nil {
			panic(err)
		}
		key.PublicKey.Yn[i] = new(bls12381.G1)
		key.PublicKey.Yn[i].ScalarMult(key.SecretKey.yn[i], bls12381.G1Generator())
		key.PublicKey.Yhatn[i] = new(bls12381.G2)
		key.PublicKey.Yhatn[i].ScalarMult(key.SecretKey.yn[i], bls12381.G2Generator())
	}

	return &key
}

// PSSign signs the attribute vector A under sk.
func PSSign(A []*bls12381.Scalar, sk *PSSecretKey) (*PSSignMsg, error) {
	var signMsg PSSignMsg
	randScalar := new(bls12381.Scalar)
	if err := randScalar.Random(rand.Reader); err != nil {
		return nil, err
	}
	signMsg.Sigma1 = new(bls12381.G1)
	signMsg.Sigma1.ScalarMult(randScalar, bls12381.G1Generator())

	signMsg.Sigma2 = new(bls12381.G1)
	signMsg.Sigma2.ScalarMult(sk.x, signMsg.Sigma1)

	var term bls12381.G1
	var Ay_n bls12381.Scalar
	for i := 0; i < len(A); i++ {
		Ay_n.Mul(A[i], sk.yn[i])
		term.ScalarMult(&Ay_n, signMsg.Sigma1)
		signMsg.Sigma2.Add(signMsg.Sigma2, &term)
	}
	return &signMsg, nil
}

// PSVerify reports whether sigma is a valid signature on A under vk.
func PSVerify(sigma *PSSignMsg, A []*bls12381.Scalar, vk *PSPublicKey) bool {
	if sigma == nil || sigma.Sigma1 == nil || sigma.Sigma2 == nil {
		return false
	}
	if vk == nil || vk.Xhat == nil || len(vk.Yn) < len(A) {
		return false
	}

	left := bls12381.Pair(sigma.Sigma2, bls12381.G2Generator())

	rightG2 := *vk.Xhat
	var term bls12381.G2
	for i := 0; i < len(A); i++ {
		term.ScalarMult(A[i], vk.Yhatn[i])
		rightG2.Add(&rightG2, &term)
	}
	right := bls12381.Pair(sigma.Sigma1, &rightG2)

	return left.IsEqual(right)
}

// RandomizeSig re-randomizes a signature, returning the new signature together with
// the blinding scalars k and t needed to verify it.
func RandomizeSig(sign *PSSignMsg) (sigma *PSSignMsg, k *bls12381.Scalar, t *bls12381.Scalar, err error) {
	if sign == nil || sign.Sigma1 == nil || sign.Sigma2 == nil {
		return nil, nil, nil, errors.New("invalid inputs to Randomize")
	}

	k = new(bls12381.Scalar)
	if err := k.Random(rand.Reader); err != nil {
		return nil, nil, nil, err
	}
	t = new(bls12381.Scalar)
	if err := t.Random(rand.Reader); err != nil {
		return nil, nil, nil, err
	}

	sigma1prime := new(bls12381.G1)
	sigma1prime.ScalarMult(k, sign.Sigma1)

	var sigma1t bls12381.G1
	sigma1t.ScalarMult(t, sign.Sigma1)

	var tmp bls12381.G1
	tmp.Add(sign.Sigma2, &sigma1t)

	sigma2prime := new(bls12381.G1)
	sigma2prime.ScalarMult(k, &tmp)

	return &PSSignMsg{
		Sigma1: sigma1prime,
		Sigma2: sigma2prime,
	}, k, t, nil
}

// VerifyRandomizedSig reports whether a randomized signature is valid on A under vk,
// given the blinding scalar t.
func VerifyRandomizedSig(sign *PSSignMsg, t *bls12381.Scalar, A []*bls12381.Scalar, vk *PSPublicKey) bool {
	if sign == nil || sign.Sigma1 == nil || sign.Sigma2 == nil {
		return false
	}
	rightG2 := *vk.Xhat
	var term bls12381.G2
	for i := 0; i < len(A); i++ {
		term.ScalarMult(A[i], vk.Yhatn[i])
		rightG2.Add(&rightG2, &term)
	}
	var g2t bls12381.G2
	g2t.ScalarMult(t, bls12381.G2Generator())
	rightG2.Add(&rightG2, &g2t)

	right := bls12381.Pair(sign.Sigma1, &rightG2)

	left := bls12381.Pair(sign.Sigma2, bls12381.G2Generator())

	return left.IsEqual(right)
}

// ToJSON serializes a signature to the flat compressed-G1 wire encoding.
func (m *PSSignMsg) ToJSON() ([]byte, error) {
	if m == nil || m.Sigma1 == nil || m.Sigma2 == nil {
		return []byte("null"), nil
	}

	sigma1Bytes := m.Sigma1.BytesCompressed()
	sigma2Bytes := m.Sigma2.BytesCompressed()
	out := make([]byte, 0, len(sigma1Bytes)+len(sigma2Bytes))
	out = append(out, sigma1Bytes...)
	out = append(out, sigma2Bytes...)
	return out, nil
}

// FromJSON parses the flat wire encoding produced by ToJSON.
func (m *PSSignMsg) FromJSON(data []byte) error {

	if string(data) == "null" {
		*m = PSSignMsg{}
		return nil
	}

	s1 := new(bls12381.G1)
	if err := s1.SetBytes(data[:bls12381.G1SizeCompressed]); err != nil {
		return fmt.Errorf("decode sigma1 G1: %w", err)
	}
	s2 := new(bls12381.G1)
	if err := s2.SetBytes(data[bls12381.G1SizeCompressed:]); err != nil {
		return fmt.Errorf("decode sigma2 G1: %w", err)
	}

	m.Sigma1 = s1
	m.Sigma2 = s2
	return nil
}
