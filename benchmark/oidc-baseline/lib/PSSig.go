package lib

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// This file implements the Pointcheval-Sanders (PS) Signature scheme.
// It provides functions for key generation, signing, verification, and randomization,
// all operating on the BLS12-381 curve.

// PSSignMsg represents a PS signature, which consists of two elements from the G1 group.
type PSSignMsg struct {
	Sigma1 *bls12381.G1
	Sigma2 *bls12381.G1
}

// PSSecretKey contains the secret components for signing messages.
type PSSecretKey struct {
	x  *bls12381.Scalar   // A secret scalar.
	yn []*bls12381.Scalar // A vector of secret scalars, one for each potential attribute.
	X  *bls12381.G1       // The public component g1^x, precomputed for efficiency.
}

// ==============for test===================
// GetSecretY returns the secret scalar vector 'yn'.
func (sk *PSSecretKey) GetSecretY() []*bls12381.Scalar {
	return sk.yn
}

// GetSecretX returns the secret scalar 'x'.
func (sk *PSSecretKey) GetSecretX() *bls12381.Scalar {
	return sk.x
}

// SetSecretX sets the secret scalar 'x' and recomputes the public component X.
func (sk *PSSecretKey) SetSecretX(x *bls12381.Scalar) {
	sk.x = x
	if sk.X == nil {
		sk.X = new(bls12381.G1)
	}
	sk.X.ScalarMult(x, bls12381.G1Generator())
}

// SetSecretY sets the secret scalar vector 'yn' at the given index.
// It also recomputes the corresponding public components Yn[i] and Yhatn[i] if provided.
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

// PSPublicKey contains the public components for verifying signatures.
type PSPublicKey struct {
	Yn    []*bls12381.G1 // Public keys for each attribute in G1.
	Xhat  *bls12381.G2   // Public key component g2^x in G2.
	Yhatn []*bls12381.G2 // Public keys for each attribute in G2.
}

// PSKey holds a pair of secret and public keys for the PS signature scheme.
type PSKey struct {
	SecretKey *PSSecretKey
	PublicKey *PSPublicKey
}

// PSKeyGen generates a new PS secret and public key pair for a given number of attributes.
// 'n' is the maximum number of attributes that can be signed.
func PSKeyGen(n int) *PSKey {
	var key PSKey
	key.SecretKey = &PSSecretKey{}
	key.PublicKey = &PSPublicKey{}

	// Generate secret scalar x and its corresponding public elements in G1 and G2.
	key.SecretKey.x = new(bls12381.Scalar)
	if err := key.SecretKey.x.Random(rand.Reader); err != nil {
		panic(err) // A failure to read from crypto/rand is a fatal error.
	}
	// X = g1^x
	key.SecretKey.X = new(bls12381.G1)
	key.SecretKey.X.ScalarMult(key.SecretKey.x, bls12381.G1Generator())
	// Xhat = g2^x
	key.PublicKey.Xhat = new(bls12381.G2)
	key.PublicKey.Xhat.ScalarMult(key.SecretKey.x, bls12381.G2Generator())

	// Generate secret scalars yn_i and their public elements for each attribute.
	key.SecretKey.yn = make([]*bls12381.Scalar, n)
	key.PublicKey.Yn = make([]*bls12381.G1, n)
	key.PublicKey.Yhatn = make([]*bls12381.G2, n)

	for i := 0; i < n; i++ {
		key.SecretKey.yn[i] = new(bls12381.Scalar)
		if err := key.SecretKey.yn[i].Random(rand.Reader); err != nil {
			panic(err)
		}
		// Yn[i] = g1^(yn[i])
		key.PublicKey.Yn[i] = new(bls12381.G1)
		key.PublicKey.Yn[i].ScalarMult(key.SecretKey.yn[i], bls12381.G1Generator())
		// Yhatn[i] = g2^(yn[i])
		key.PublicKey.Yhatn[i] = new(bls12381.G2)
		key.PublicKey.Yhatn[i].ScalarMult(key.SecretKey.yn[i], bls12381.G2Generator())
	}

	return &key
}

// Sign creates a PS signature on a vector of attributes 'A' using the secret key 'sk'.
func PSSign(A []*bls12381.Scalar, sk *PSSecretKey) (*PSSignMsg, error) {
	// 1. Choose a random sigma1 from G1.
	var signMsg PSSignMsg
	randScalar := new(bls12381.Scalar)
	if err := randScalar.Random(rand.Reader); err != nil {
		return nil, err
	}
	// sigma1 = g1^randScalar
	signMsg.Sigma1 = new(bls12381.G1)
	signMsg.Sigma1.ScalarMult(randScalar, bls12381.G1Generator())

	// 2. Compute sigma2 = sigma1^x * Π(sigma1^(A[i]*yn[i])).
	signMsg.Sigma2 = new(bls12381.G1)
	signMsg.Sigma2.ScalarMult(sk.x, signMsg.Sigma1)

	// Accumulate the product for each attribute.
	var term bls12381.G1
	var Ay_n bls12381.Scalar
	for i := 0; i < len(A); i++ {
		Ay_n.Mul(A[i], sk.yn[i]) // Ay_n = A[i] * yn[i]
		term.ScalarMult(&Ay_n, signMsg.Sigma1)
		signMsg.Sigma2.Add(signMsg.Sigma2, &term) // sigma2 += sigma1^(A[i]*yn[i])
	}
	return &signMsg, nil
}

// Verify checks if a PS signature is valid for a given attribute vector 'A' and public key 'vk'.
func PSVerify(sigma *PSSignMsg, A []*bls12381.Scalar, vk *PSPublicKey) bool {
	if sigma == nil || sigma.Sigma1 == nil || sigma.Sigma2 == nil {
		return false
	}
	if vk == nil || vk.Xhat == nil || len(vk.Yn) < len(A) {
		return false
	}

	// Verification check: e(sigma2, g2) == e(sigma1, Xhat * Π(Yhatn[i]^A[i]))

	// Left side of the equation: e(sigma2, g2)
	left := bls12381.Pair(sigma.Sigma2, bls12381.G2Generator())

	// Right side of the equation:
	// First, compute the term in G2: Xhat * Π(Yhatn[i]^A[i])
	rightG2 := *vk.Xhat // Create a copy of vk.Xhat by dereferencing the pointer.
	var term bls12381.G2
	for i := 0; i < len(A); i++ {
		term.ScalarMult(A[i], vk.Yhatn[i]) // term = Yhatn[i]^A[i]
		rightG2.Add(&rightG2, &term)
	}
	// Then, compute the pairing: e(sigma1, &rightG2)
	right := bls12381.Pair(sigma.Sigma1, &rightG2)

	return left.IsEqual(right)
}

// Randomize produces a randomized version of a signature.
// It returns the new signature and the random scalars 'k' and 't' used.
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

	// sigma1' = sigma1^k
	sigma1prime := new(bls12381.G1)
	sigma1prime.ScalarMult(k, sign.Sigma1)

	// sigma2' = (sigma2 * sigma1^t)^k
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

// VerifyRandomized checks a randomized signature.
func VerifyRandomizedSig(sign *PSSignMsg, t *bls12381.Scalar, A []*bls12381.Scalar, vk *PSPublicKey) bool {
	if sign == nil || sign.Sigma1 == nil || sign.Sigma2 == nil {
		return false
	}
	// The verification equation for a randomized signature is:
	// e(sigma2', g2) == e(sigma1', Xhat * Π(Yhatn[i]^A[i]) * g2^t)

	// Right side of the equation:
	// First, compute the term in G2: Xhat * Π(Yhatn[i]^A[i]) * g2^t
	rightG2 := *vk.Xhat // Create a copy of vk.Xhat
	var term bls12381.G2
	for i := 0; i < len(A); i++ {
		term.ScalarMult(A[i], vk.Yhatn[i]) // term = Yhatn[i]^A[i]
		rightG2.Add(&rightG2, &term)
	}
	var g2t bls12381.G2
	g2t.ScalarMult(t, bls12381.G2Generator())
	rightG2.Add(&rightG2, &g2t)

	// Then, compute the pairing: e(sigma1', &rightG2)
	right := bls12381.Pair(sign.Sigma1, &rightG2)

	// Left side of the equation: e(sigma2', g2)
	left := bls12381.Pair(sign.Sigma2, bls12381.G2Generator())

	return left.IsEqual(right)
}

func (m *PSSignMsg) ToJSON() ([]byte, error) {
	if m == nil || m.Sigma1 == nil || m.Sigma2 == nil {
		return []byte("null"), nil
	}

	// 将 G1 点压缩为字节，然后编码为 base64 字符串
	sigma1Bytes := m.Sigma1.BytesCompressed()
	sigma2Bytes := m.Sigma2.BytesCompressed()
	out := make([]byte, 0, len(sigma1Bytes)+len(sigma2Bytes))
	out = append(out, sigma1Bytes...)
	out = append(out, sigma2Bytes...)
	return out, nil
}

// UnmarshalJSON implements json.Unmarshaler for PSSignMsg
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
