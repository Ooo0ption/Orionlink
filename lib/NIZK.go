// Schnorr-style non-interactive zero-knowledge proofs over BLS12-381 G1, made
// non-interactive by the Fiat-Shamir transform.
package lib

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// Proof is a Schnorr NIZK over G1: the points P and R and the response scalar Z.
type Proof struct {
	P       *bls12381.G1
	R       *bls12381.G1
	Z       *bls12381.Scalar
	context []byte
}

// MultiExpProof proves knowledge of alpha and the vector beta_i behind
// y = g^alpha * prod_i Y_i^{beta_i}.
type MultiExpProof struct {
	C1 *bls12381.G1
	R1 *bls12381.G1
	Z0 *bls12381.Scalar
	Zs []*bls12381.Scalar
}

// GenerateKey returns a random secret scalar and its public point P = x*G1.
func GenerateKey() (*bls12381.Scalar, *bls12381.G1, error) {
	var x bls12381.Scalar
	if err := x.Random(rand.Reader); err != nil {
		return nil, nil, err
	}
	var P bls12381.G1
	P.ScalarMult(&x, bls12381.G1Generator())
	return &x, &P, nil
}

// computeChallenge derives the Fiat-Shamir challenge from P and R.
func computeChallenge(P, R *bls12381.G1) *bls12381.Scalar {
	hsh := sha256.New()
	hsh.Write(P.BytesCompressed())
	hsh.Write(R.BytesCompressed())
	var c bls12381.Scalar
	c.SetBytes(hsh.Sum(nil))
	return &c
}

// Prove produces a Schnorr NIZK of knowledge of x behind P = x*G1.
func Prove(priv *bls12381.Scalar, P *bls12381.G1) (*Proof, error) {
	if priv == nil || P == nil {
		return nil, errors.New("invalid inputs")
	}
	var r bls12381.Scalar
	if err := r.Random(rand.Reader); err != nil {
		return nil, err
	}
	var R bls12381.G1
	R.ScalarMult(&r, bls12381.G1Generator())

	c := computeChallenge(P, &R)

	var z bls12381.Scalar
	z.Mul(c, priv)
	z.Add(&z, &r)
	return &Proof{P: P, R: &R, Z: &z}, nil
}

// Verify reports whether a Schnorr NIZK proof holds.
func Verify(proof *Proof) (bool, error) {
	if proof == nil || proof.P == nil || proof.R == nil || proof.Z == nil {
		return false, errors.New("invalid inputs")
	}
	c := computeChallenge(proof.P, proof.R)

	var zG bls12381.G1
	zG.ScalarMult(proof.Z, bls12381.G1Generator())

	var cP bls12381.G1
	cP.ScalarMult(c, proof.P)
	var RpluscP bls12381.G1
	RpluscP.Add(proof.R, &cP)

	return zG.IsEqual(&RpluscP), nil
}

// computeMultiExpChallenge derives the Fiat-Shamir challenge for a
// multi-exponentiation proof.
func computeMultiExpChallenge(Ys []*bls12381.G1, P *bls12381.G1, R *bls12381.G1) *bls12381.Scalar {
	hsh := sha256.New()
	for i := range Ys {
		hsh.Write(Ys[i].BytesCompressed())
	}
	hsh.Write(P.BytesCompressed())
	hsh.Write(R.BytesCompressed())
	var c bls12381.Scalar
	c.SetBytes(hsh.Sum(nil))
	return &c
}

// ProveMultiExp proves knowledge of (alpha, betas) behind
// C = g^alpha * prod_i Y_i^{beta_i}.
func ProveMultiExp(alpha *bls12381.Scalar, betas []*bls12381.Scalar, C *bls12381.G1, g1 *bls12381.G1, Ys []*bls12381.G1) (*MultiExpProof, error) {
	if alpha == nil || C == nil || g1 == nil {
		return nil, errors.New("invalid inputs to ProveMultiExp")
	}
	if len(betas) != len(Ys) {
		return nil, errors.New("betas and bases length mismatch")
	}

	var r0 bls12381.Scalar
	if err := r0.Random(rand.Reader); err != nil {
		return nil, err
	}
	rs := make([]bls12381.Scalar, len(betas))
	for i := range betas {
		if err := rs[i].Random(rand.Reader); err != nil {
			return nil, err
		}
	}

	var R1 bls12381.G1
	R1.ScalarMult(&r0, g1)
	for i := range rs {
		var tmp bls12381.G1
		tmp.ScalarMult(&rs[i], Ys[i])
		R1.Add(&R1, &tmp)
	}

	c := computeMultiExpChallenge(Ys, C, &R1)

	var z0 bls12381.Scalar
	z0.Mul(c, alpha)
	z0.Add(&z0, &r0)

	zs := make([]*bls12381.Scalar, len(betas))
	for i := range betas {
		zs[i] = new(bls12381.Scalar)
		zs[i].Mul(c, betas[i])
		zs[i].Add(zs[i], &rs[i])
	}

	return &MultiExpProof{C1: C, R1: &R1, Z0: &z0, Zs: zs}, nil
}

// VerifyMultiExp reports whether a multi-exponentiation proof holds.
func VerifyMultiExp(g1 *bls12381.G1, Ys []*bls12381.G1, proof *MultiExpProof) (bool, error) {
	if proof == nil || proof.C1 == nil || proof.R1 == nil || proof.Z0 == nil || g1 == nil {
		return false, errors.New("invalid inputs to VerifyMultiExp")
	}
	if len(proof.Zs) != len(Ys) {
		return false, errors.New("proof zs and bases length mismatch")
	}

	c := computeMultiExpChallenge(Ys, proof.C1, proof.R1)

	var left bls12381.G1
	left.ScalarMult(proof.Z0, g1)
	for i := range proof.Zs {
		var tmp bls12381.G1
		tmp.ScalarMult(proof.Zs[i], Ys[i])
		left.Add(&left, &tmp)
	}

	var C1c bls12381.G1
	C1c.ScalarMult(c, proof.C1)
	var right bls12381.G1
	right.Add(proof.R1, &C1c)

	return left.IsEqual(&right), nil
}
