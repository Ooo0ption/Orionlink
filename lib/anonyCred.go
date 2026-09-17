// Anonymous credentials over PS signatures: blind issuance, unblinding, and
// unlinkable presentation.
package lib

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// PrepareBlindSign commits to the prover's hidden attributes and proves knowledge
// of them, returning the proof and the blinding factor d.
func PrepareBlindSign(hiddenAttrs []*bls12381.Scalar, Yh []*bls12381.G1) (*MultiExpProof, *bls12381.Scalar, error) {
	if len(hiddenAttrs) != len(Yh) {
		return nil, nil, errors.New("hiddenAttrs and Yh length mismatch")
	}
	if Yh == nil {
		return nil, nil, errors.New("missing issuer public key components (Yh)")
	}

	var d bls12381.Scalar
	if err := d.Random(rand.Reader); err != nil {
		return nil, nil, err
	}

	Ci := new(bls12381.G1)
	Ci.ScalarMult(&d, bls12381.G1Generator())
	var term bls12381.G1
	for i, h := range hiddenAttrs {
		Yi := Yh[i]
		term.ScalarMult(h, Yi)
		Ci.Add(Ci, &term)
	}

	proof, err := ProveMultiExp(&d, hiddenAttrs, Ci, bls12381.G1Generator(), Yh)
	if err != nil {
		return nil, nil, err
	}

	return proof, &d, nil
}

// BlindSign verifies the prover's request and issues a blinded signature over the
// hidden commitment together with the public attributes.
func BlindSign(sk *PSSecretKey, vk *PSPublicKey, req *MultiExpProof, publicAttrs []*bls12381.Scalar) (*PSSignMsg, error) {
	if sk == nil || req == nil || vk == nil || sk.X == nil {
		return nil, errors.New("invalid inputs or incomplete issuer key")
	}
	if req.C1 == nil || req.R1 == nil || req.Z0 == nil || req.Zs == nil {
		return nil, errors.New("missing elements in blind request")
	}

	Yh := vk.Yn[len(publicAttrs):]
	if len(Yh) != len(req.Zs) {
		return nil, errors.New("issuer public key (Yh) length mismatch with multi-proof (Zs)")
	}

	ok, err := VerifyMultiExp(bls12381.G1Generator(), Yh, req)
	if err != nil || !ok {
		return nil, errors.New("multi-exponent proof verification failed")
	}

	var r bls12381.Scalar
	if err := r.Random(rand.Reader); err != nil {
		return nil, err
	}

	sigma1 := new(bls12381.G1)
	sigma1.ScalarMult(&r, bls12381.G1Generator())

	Pprime := *sk.X
	Pprime.Add(&Pprime, req.C1)

	var term bls12381.G1
	for k, a := range publicAttrs {
		term.ScalarMult(a, vk.Yn[k])
		Pprime.Add(&Pprime, &term)
	}
	sigma2 := new(bls12381.G1)
	sigma2.ScalarMult(&r, &Pprime)

	return &PSSignMsg{Sigma1: sigma1, Sigma2: sigma2}, nil
}

// Unblind removes the blinding factor d from an issued signature, yielding the
// final credential.
func Unblind(hatSigma *PSSignMsg, d *bls12381.Scalar) (*PSSignMsg, error) {
	if hatSigma == nil || d == nil {
		return nil, errors.New("invalid inputs to Unblind")
	}

	temp := new(bls12381.G1)
	temp.ScalarMult(d, hatSigma.Sigma1)
	var sigma2 bls12381.G1
	var negTemp bls12381.G1
	negTemp = *temp
	negTemp.Neg()
	sigma2.Add(hatSigma.Sigma2, &negTemp)

	return &PSSignMsg{Sigma1: hatSigma.Sigma1, Sigma2: &sigma2}, nil
}

// CredentialPresentation is one showing of an anonymous credential.
type AnoyCredPresentation struct {
	Sigma   *PSSignMsg
	C       *bls12381.G2
	R       *bls12381.G2
	Z0      *bls12381.Scalar
	Zs      []*bls12381.Scalar
	Context []byte
}

// AnoyCredPresent randomizes a credential and proves knowledge of its hidden
// attributes, producing an unlinkable presentation.
func AnoyCredPresent(sigma *PSSignMsg, t *bls12381.Scalar, hiddenAttrs, r []*bls12381.Scalar,
	vk *PSPublicKey, context []byte) (*AnoyCredPresentation, error) {

	if len(hiddenAttrs) != len(r) || len(hiddenAttrs) != len(vk.Yhatn) {
		return nil, errors.New("hiddenAttrs, r, and Yhatn must have the same length")
	}

	C2 := new(bls12381.G2)
	C2.ScalarMult(t, bls12381.G2Generator())
	var termG2 bls12381.G2
	for i, a := range hiddenAttrs {
		termG2.ScalarMult(a, vk.Yhatn[i])
		C2.Add(C2, &termG2)
	}

	var r0 bls12381.Scalar
	if err := r0.Random(rand.Reader); err != nil {
		return nil, err
	}

	R2 := new(bls12381.G2)
	R2.ScalarMult(&r0, bls12381.G2Generator())
	for i, ri := range r {
		termG2.ScalarMult(ri, vk.Yhatn[i])
		R2.Add(R2, &termG2)
	}

	c := computeAnoyCredChallenge(vk.Yhatn, C2, R2, context)

	var z0 bls12381.Scalar
	z0.Mul(c, t)
	z0.Add(&z0, &r0)

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

// VerifyAnoyCredPresent reports whether a credential presentation is valid.
func VerifyAnoyCredPresent(ap *AnoyCredPresentation, vk *PSPublicKey) (bool, error) {
	if ap == nil || vk == nil || ap.C == nil || ap.R == nil || ap.Z0 == nil {
		return false, errors.New("invalid inputs for presentation verification")
	}
	if len(ap.Zs) != len(vk.Yhatn) {
		return false, errors.New("proof zs length mismatch with public key bases")
	}

	c := computeAnoyCredChallenge(vk.Yhatn, ap.C, ap.R, ap.Context)

	var left bls12381.G2
	left.ScalarMult(ap.Z0, bls12381.G2Generator())
	var termG2 bls12381.G2
	for i, zi := range ap.Zs {
		termG2.ScalarMult(zi, vk.Yhatn[i])
		left.Add(&left, &termG2)
	}

	var right bls12381.G2
	right.ScalarMult(c, ap.C)
	right.Add(&right, ap.R)

	if !left.IsEqual(&right) {
		return false, errors.New("commitment proof verification failed")
	}

	var XhatC2 bls12381.G2
	XhatC2.Add(vk.Xhat, ap.C)

	e1 := bls12381.Pair(ap.Sigma.Sigma2, bls12381.G2Generator())
	e2 := bls12381.Pair(ap.Sigma.Sigma1, &XhatC2)

	if !e1.IsEqual(e2) {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}

// computeAnoyCredChallenge derives the Fiat-Shamir challenge for a presentation.
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
