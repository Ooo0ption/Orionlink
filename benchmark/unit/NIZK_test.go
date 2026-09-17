// Unit tests for the Schnorr and multi-exponentiation NIZK proofs.
package unit

import (
	"crypto/rand"
	"secure-sso/lib"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// TestSchnorrNIZK exercises both sides of the Schnorr protocol: an honest proof
// verifies, and one with a tampered response scalar does not.
func TestSchnorrNIZK(t *testing.T) {
	priv, pub, err := lib.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	proof, err := lib.Prove(priv, pub)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	t.Run("completeness", func(t *testing.T) {
		ok, err := lib.Verify(proof)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !ok {
			t.Fatal("Schnorr NIZK proof verification failed")
		}
	})

	t.Run("soundness/tampered_Z_rejected", func(t *testing.T) {
		var delta bls12381.Scalar
		delta.SetUint64(1)
		tamperedZ := new(bls12381.Scalar)
		tamperedZ.Add(proof.Z, &delta)
		tampered := *proof
		tampered.Z = tamperedZ
		if ok, _ := lib.Verify(&tampered); ok {
			t.Error("Verify accepted a proof with tampered Z — soundness broken")
		}
	})
}

func TestMultiExpNIZKProof(t *testing.T) {
	n := 3
	var alpha bls12381.Scalar
	if err := alpha.Random(rand.Reader); err != nil {
		t.Fatalf("alpha random failed: %v", err)
	}
	betas := make([]*bls12381.Scalar, n)
	Ys := make([]*bls12381.G1, n)
	for i := 0; i < n; i++ {
		betas[i] = new(bls12381.Scalar)
		if err := betas[i].Random(rand.Reader); err != nil {
			t.Fatalf("beta random failed: %v", err)
		}
		Ys[i] = new(bls12381.G1)
		var tmp bls12381.Scalar
		if err := tmp.Random(rand.Reader); err != nil {
			t.Fatalf("Ys random failed: %v", err)
		}
		Ys[i].ScalarMult(&tmp, bls12381.G1Generator())
	}

	g1 := bls12381.G1Generator()
	var C bls12381.G1
	C.ScalarMult(&alpha, g1)
	for i := 0; i < n; i++ {
		var tmp bls12381.G1
		tmp.ScalarMult(betas[i], Ys[i])
		C.Add(&C, &tmp)
	}

	proof, err := lib.ProveMultiExp(&alpha, betas, &C, g1, Ys)
	if err != nil {
		t.Fatalf("ProveMultiExp failed: %v", err)
	}

	ok, err := lib.VerifyMultiExp(g1, Ys, proof)
	if err != nil {
		t.Fatalf("VerifyMultiExp failed: %v", err)
	}
	if !ok {
		t.Fatal("MultiExp NIZK proof verification failed")
	}
}
