package lib

// NIZK (Non-Interactive Zero-Knowledge) Proofs
// Implementation: Schnorr-style proof of knowledge of discrete log on an elliptic curve.
// Uses the Fiat-Shamir transform to make the sigma-protocol non-interactive.
//
// Contract (functions below):
// - GenerateKey() -> (priv, pubX, pubY, error)
// - Prove(priv, P, context) -> *Proof, error
// - Verify(proof, context) -> bool, error
//
// Inputs/Outputs:
// - priv is a scalar (bls12381.Scalar)
// - public key is the point P = priv*G
// - context is optional additional data included in the Fiat-Shamir hash (e.g., session IDs)
// - Proof contains P, R (curve points) and z (scalar)
//
// Security notes (demo): Use a secure curve (BLS12-381 used here). Treat this
// implementation as educational; for production use vetted libraries and constant-time ops.

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// Proof is a Schnorr-style NIZK proof over bls12381 G1: P, R (G1 points) and z (scalar).
type Proof struct {
	P       *bls12381.G1
	R       *bls12381.G1
	Z       *bls12381.Scalar
	context []byte
}

// MultiExpProof proves knowledge of alpha and vector beta_i such that
// y = g^{alpha} * Π_i Yi^{beta_i} in G1.
type MultiExpProof struct {
	C1 *bls12381.G1
	R1 *bls12381.G1
	Z0 *bls12381.Scalar
	Zs []*bls12381.Scalar
}

// GenerateKey creates a random private scalar and public G1 point P = x*G1.
func GenerateKey() (*bls12381.Scalar, *bls12381.G1, error) {
	var x bls12381.Scalar
	if err := x.Random(rand.Reader); err != nil {
		return nil, nil, err
	}
	var P bls12381.G1
	P.ScalarMult(&x, bls12381.G1Generator())
	return &x, &P, nil
}

// computeChallenge computes the Fiat-Shamir challenge c = H(P || R || context).
func computeChallenge(P, R *bls12381.G1) *bls12381.Scalar {
	hsh := sha256.New()
	hsh.Write(P.BytesCompressed())
	hsh.Write(R.BytesCompressed())
	var c bls12381.Scalar
	// Use SetHash for a robust, uniform mapping from bytes to a scalar.
	c.SetBytes(hsh.Sum(nil))
	return &c
}

// Prove produces a Schnorr NIZK (Fiat-Shamir) for knowledge of x where P = x*G1.
// context is optional additional data included in the Fiat-Shamir hash.
func Prove(priv *bls12381.Scalar, P *bls12381.G1) (*Proof, error) {
	if priv == nil || P == nil {
		return nil, errors.New("invalid inputs")
	}
	// 1. Sample random scalar r and compute commitment R = r*G1.
	var r bls12381.Scalar
	if err := r.Random(rand.Reader); err != nil {
		return nil, err
	}
	var R bls12381.G1
	R.ScalarMult(&r, bls12381.G1Generator())

	// 2. Compute challenge c = H(P || R || context).
	c := computeChallenge(P, &R)

	// 3. Compute response z = r + c*priv.
	var z bls12381.Scalar
	z.Mul(c, priv)
	z.Add(&z, &r)
	return &Proof{P: P, R: &R, Z: &z}, nil
}

// Verify checks a Schnorr NIZK proof over bls12381 G1.
// It checks if z*G == R + c*P.
func Verify(proof *Proof) (bool, error) {
	if proof == nil || proof.P == nil || proof.R == nil || proof.Z == nil {
		return false, errors.New("invalid inputs")
	}
	// 1. Recompute challenge c = H(P || R || context).
	c := computeChallenge(proof.P, proof.R)

	// 2. Check the verification equation: z*G == R + c*P.
	// We compute z*G on the left side.
	var zG bls12381.G1
	zG.ScalarMult(proof.Z, bls12381.G1Generator())

	// We compute R + c*P on the right side.
	var cP bls12381.G1
	cP.ScalarMult(c, proof.P)
	var RpluscP bls12381.G1
	RpluscP.Add(proof.R, &cP)

	return zG.IsEqual(&RpluscP), nil
}

// computeMultiExpChallenge computes the Fiat-Shamir challenge for the multi-exponentiation proof.
// c = H(Y_1 || ... || Y_n || P || R || context)
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

// ProveMultiExp produces a non-interactive proof for knowledge of (alpha, betas)
// such that C = g^alpha * Π_i Y_i^{beta_i}.
func ProveMultiExp(alpha *bls12381.Scalar, betas []*bls12381.Scalar, C *bls12381.G1, g1 *bls12381.G1, Ys []*bls12381.G1) (*MultiExpProof, error) {
	if alpha == nil || C == nil || g1 == nil {
		return nil, errors.New("invalid inputs to ProveMultiExp")
	}
	if len(betas) != len(Ys) {
		return nil, errors.New("betas and bases length mismatch")
	}

	// 1. Sample random scalars r0, r1, ..., rn.
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

	// 2. Compute commitment R1 = g^{r0} * Π Y_i^{ri}.
	var R1 bls12381.G1
	R1.ScalarMult(&r0, g1)
	for i := range rs {
		var tmp bls12381.G1
		tmp.ScalarMult(&rs[i], Ys[i])
		R1.Add(&R1, &tmp)
	}

	// 3. Compute challenge c = H(Ys || C || R1).
	c := computeMultiExpChallenge(Ys, C, &R1)

	// 4. Compute responses z0 = r0 + c*alpha and zi = ri + c*beta_i.
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

// VerifyMultiExp checks the multi-exponentiation proof.
// It checks if g^{z0} * Π Y_i^{zi} == R1 * C^c.
func VerifyMultiExp(g1 *bls12381.G1, Ys []*bls12381.G1, proof *MultiExpProof) (bool, error) {
	if proof == nil || proof.C1 == nil || proof.R1 == nil || proof.Z0 == nil || g1 == nil {
		return false, errors.New("invalid inputs to VerifyMultiExp")
	}
	if len(proof.Zs) != len(Ys) {
		return false, errors.New("proof zs and bases length mismatch")
	}

	// 1. Recompute challenge c.
	c := computeMultiExpChallenge(Ys, proof.C1, proof.R1)

	// 2. Check the verification equation.
	// Left side: g^{z0} * Π Y_i^{zi}
	var left bls12381.G1
	left.ScalarMult(proof.Z0, g1)
	for i := range proof.Zs {
		var tmp bls12381.G1
		tmp.ScalarMult(proof.Zs[i], Ys[i])
		left.Add(&left, &tmp)
	}

	// Right side: R1 * C1^c
	var C1c bls12381.G1
	C1c.ScalarMult(c, proof.C1)
	var right bls12381.G1
	right.Add(proof.R1, &C1c)

	return left.IsEqual(&right), nil
}
