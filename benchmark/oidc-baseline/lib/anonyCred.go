package lib

// Anonymous Credential Based on PS Signature and NIZK
// NOTE: This is a demo helper library that shows how to build an
// "anonymous credential" workflow on top of the PS signature and
// the simple Schnorr-style NIZK implemented in this repository.
//
// The implementation below uses commitments to hidden attributes
// (Ci = G1^{attr}) and has the issuer sign the hash of those
// commitments together with public attributes. The prover creates
// NIZK proofs of knowledge of hidden attributes for the commitments
// and presents them to the issuer. The issuer verifies the proofs
// and signs the (commitment-hash || public attributes) vector.
//
// This is a demonstrative (educational) construction and not a
// production-ready blind-PS protocol. A full blind PS protocol
// requires interactive blinding or dedicated algebraic transforms.

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// PrepareBlindSign (prover)
// Creates a commitment to hidden attributes and proves knowledge of them.
// - hiddenAttrs: A slice of hidden attribute scalars.
// - Yh: The issuer's public key components corresponding to the hidden attributes.
// - context: Optional context for the NIZK proof.
// Returns a multi-exponentiation proof, a blinding factor 'd', and an error.
func PrepareBlindSign(hiddenAttrs []*bls12381.Scalar, Yh []*bls12381.G1) (*MultiExpProof, *bls12381.Scalar, error) {
	if len(hiddenAttrs) != len(Yh) {
		return nil, nil, errors.New("hiddenAttrs and Yh length mismatch")
	}
	if Yh == nil {
		return nil, nil, errors.New("missing issuer public key components (Yh)")
	}

	// Prover chooses a secret blinding factor 'd'.
	var d bls12381.Scalar
	if err := d.Random(rand.Reader); err != nil {
		return nil, nil, err
	}

	// Create commitment C = g1^d * Π(Yi^hi)
	Ci := new(bls12381.G1)
	Ci.ScalarMult(&d, bls12381.G1Generator())
	var term bls12381.G1
	for i, h := range hiddenAttrs {
		Yi := Yh[i]
		term.ScalarMult(h, Yi)
		Ci.Add(Ci, &term)
	}

	// Prove knowledge of the secret blinding factor 'd' and the hidden attributes.
	proof, err := ProveMultiExp(&d, hiddenAttrs, Ci, bls12381.G1Generator(), Yh)
	if err != nil {
		return nil, nil, err
	}

	return proof, &d, nil
}

// BlindSign performs the blind signing operation by the issuer.
// - sk: Issuer's secret key.
// - vk: Issuer's public key.
// - req: Blind request from the prover, containing commitments and proofs.
// - publicAttrs: Attributes that are public and known to the issuer.
// Returns a blinded signature.
func BlindSign(sk *PSSecretKey, vk *PSPublicKey, req *MultiExpProof, publicAttrs []*bls12381.Scalar) (*PSSignMsg, error) {
	if sk == nil || req == nil || vk == nil || sk.X == nil {
		return nil, errors.New("invalid inputs or incomplete issuer key")
	}
	if req.C1 == nil || req.R1 == nil || req.Z0 == nil || req.Zs == nil {
		return nil, errors.New("missing elements in blind request")
	}

	// The public key components for hidden attributes are the ones not used for public attributes.
	Yh := vk.Yn[len(publicAttrs):]
	if len(Yh) != len(req.Zs) {
		return nil, errors.New("issuer public key (Yh) length mismatch with multi-proof (Zs)")
	}

	// Verify the prover's multi-exponentiation proof.
	// This proves they know the exponents (d, hiddenAttrs) for the commitment C1.
	ok, err := VerifyMultiExp(bls12381.G1Generator(), Yh, req) // Assuming nil context if not passed in req
	if err != nil || !ok {
		return nil, errors.New("multi-exponent proof verification failed")
	}

	// Issuer chooses a random 'r' for signing.
	var r bls12381.Scalar
	if err := r.Random(rand.Reader); err != nil {
		return nil, err
	}

	// sigma1 = g1^r
	sigma1 := new(bls12381.G1)
	sigma1.ScalarMult(&r, bls12381.G1Generator())

	// P' = X + C1 + Σ(Y_pub_i ^ a_pub_i)
	Pprime := *sk.X
	Pprime.Add(&Pprime, req.C1)

	var term bls12381.G1
	for k, a := range publicAttrs {
		term.ScalarMult(a, vk.Yn[k])
		Pprime.Add(&Pprime, &term)
	}
	// sigma2 = (P')^r
	sigma2 := new(bls12381.G1)
	sigma2.ScalarMult(&r, &Pprime)

	return &PSSignMsg{Sigma1: sigma1, Sigma2: sigma2}, nil
}

// Unblind allows the prover to unblind the signature received from the issuer.
// - hatSigma: The blinded signature from the issuer.
// - d: The prover's secret blinding scalar.
// Returns the final, unblinded signature.
func Unblind(hatSigma *PSSignMsg, d *bls12381.Scalar) (*PSSignMsg, error) {
	if hatSigma == nil || d == nil {
		return nil, errors.New("invalid inputs to Unblind")
	}

	// To unblind, subtract the blinding factor from sigma2:
	// sigma2 = hatSigma2 / (hatSigma1^d) which is equivalent to
	// sigma2 = hatSigma.Sigma2 - d*hatSigma.Sigma1 in additive notation.
	temp := new(bls12381.G1)
	temp.ScalarMult(d, hatSigma.Sigma1)
	var sigma2 bls12381.G1
	var negTemp bls12381.G1
	negTemp = *temp
	negTemp.Neg()
	sigma2.Add(hatSigma.Sigma2, &negTemp)

	return &PSSignMsg{Sigma1: hatSigma.Sigma1, Sigma2: &sigma2}, nil
}

// CredentialPresentation defines the structure for presenting an anonymous credential.
type AnoyCredPresentation struct {
	Sigma   *PSSignMsg         // Randomized signature
	C       *bls12381.G2       // Commitment to hidden attributes
	R       *bls12381.G2       // Randomness for the commitment
	Z0      *bls12381.Scalar   // Response for the blinding factor 't'
	Zs      []*bls12381.Scalar // Responses for hidden attributes
	Context []byte
}

// AnoyCredPresent creates a presentation of an anonymous credential, proving knowledge of hidden attributes.
// This implementation only supports hidden attributes.
func AnoyCredPresent(sigma *PSSignMsg, t *bls12381.Scalar, hiddenAttrs, r []*bls12381.Scalar,
	vk *PSPublicKey, context []byte) (*AnoyCredPresentation, error) {

	if len(hiddenAttrs) != len(r) || len(hiddenAttrs) != len(vk.Yhatn) {
		return nil, errors.New("hiddenAttrs, r, and Yhatn must have the same length")
	}

	// 1. Create commitment C2 = g2^t * Π(Yhat_i ^ A_i)
	C2 := new(bls12381.G2)
	C2.ScalarMult(t, bls12381.G2Generator())
	var termG2 bls12381.G2
	for i, a := range hiddenAttrs {
		termG2.ScalarMult(a, vk.Yhatn[i])
		C2.Add(C2, &termG2)
	}

	// 2. Sample random scalar r0 for the blinding factor t.
	var r0 bls12381.Scalar
	if err := r0.Random(rand.Reader); err != nil {
		return nil, err
	}

	// 3. Compute commitment to randomness R2 = g2^r0 * Π(Yhat_i ^ r_i)
	R2 := new(bls12381.G2)
	R2.ScalarMult(&r0, bls12381.G2Generator())
	for i, ri := range r {
		termG2.ScalarMult(ri, vk.Yhatn[i])
		R2.Add(R2, &termG2)
	}

	// 4. Compute challenge c = H(Yhat || C2 || R2 || context)
	c := computeAnoyCredChallenge(vk.Yhatn, C2, R2, context)

	// 5. Compute response z0 = r0 + c*t
	var z0 bls12381.Scalar
	z0.Mul(c, t)
	z0.Add(&z0, &r0)

	// 6. Compute responses zi = ri + c*A_i
	zs := make([]*bls12381.Scalar, len(hiddenAttrs))
	for i, attr := range hiddenAttrs {
		zs[i] = new(bls12381.Scalar)
		zs[i].Mul(c, attr)
		zs[i].Add(zs[i], r[i])
	}

	return &AnoyCredPresentation{
		Sigma:   sigma,
		C:       C2,
		R:       R2,
		Z0:      &z0,
		Zs:      zs,
		Context: context,
	}, nil
}

// VerifyAnoyCredPresent verifies the anonymous credential presentation.
func VerifyAnoyCredPresent(ap *AnoyCredPresentation, vk *PSPublicKey) (bool, error) {
	if ap == nil || vk == nil || ap.C == nil || ap.R == nil || ap.Z0 == nil {
		return false, errors.New("invalid inputs for presentation verification")
	}
	if len(ap.Zs) != len(vk.Yhatn) {
		return false, errors.New("proof zs length mismatch with public key bases")
	}

	// 1. Recompute challenge c = H(Yhat || C || R || context)
	c := computeAnoyCredChallenge(vk.Yhatn, ap.C, ap.R, ap.Context)

	// 2. Verify the commitment proof: check if g2^z0 * Π(Yhat_i^zi) == R * C^c
	// Left side: g2^z0 * Π(Yhat_i^zi)
	var left bls12381.G2
	left.ScalarMult(ap.Z0, bls12381.G2Generator())
	var termG2 bls12381.G2
	for i, zi := range ap.Zs {
		termG2.ScalarMult(zi, vk.Yhatn[i])
		left.Add(&left, &termG2)
	}

	// Right side: R + c*C (in additive notation)
	var right bls12381.G2
	right.ScalarMult(c, ap.C)
	right.Add(&right, ap.R)

	if !left.IsEqual(&right) {
		return false, errors.New("commitment proof verification failed")
	}

	// 3. Verify the randomized signature: check if e(sigma2, g2) == e(sigma1, Xhat + C)
	var XhatC2 bls12381.G2
	XhatC2.Add(vk.Xhat, ap.C) // Xhat + C

	e1 := bls12381.Pair(ap.Sigma.Sigma2, bls12381.G2Generator())
	e2 := bls12381.Pair(ap.Sigma.Sigma1, &XhatC2)

	if !e1.IsEqual(e2) {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}

// computeAnoyCredChallenge computes the Fiat-Shamir challenge for the anonymous credential presentation.
func computeAnoyCredChallenge(Yhatn []*bls12381.G2, C, R *bls12381.G2, context []byte) *bls12381.Scalar {
	hsh := sha256.New()
	for _, y := range Yhatn {
		hsh.Write(y.BytesCompressed())
	}
	hsh.Write(C.BytesCompressed())
	hsh.Write(R.BytesCompressed())
	if context != nil {
		hsh.Write(context)
	}
	var c bls12381.Scalar
	c.SetBytes(hsh.Sum(nil))
	return &c
}
