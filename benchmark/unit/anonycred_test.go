// Unit tests for anonymous-credential issuance and presentation.
package unit

import (
	"crypto/rand"
	"secure-sso/lib"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// TestAnonymousCredentialIssuance walks the blind issuance protocol end to end:
// request, blind signature, unblinding, and verification.
func TestAnonymousCredentialIssuance(t *testing.T) {
	keys := lib.PSKeyGen(2)

	var publicAttr, hiddenAttr bls12381.Scalar
	publicAttr.SetBytes([]byte("1996"))
	hiddenAttr.SetBytes([]byte("123456789"))

	Yh := []*bls12381.G1{keys.PublicKey.Yn[1]}

	proof, d, err := lib.PrepareBlindSign([]*bls12381.Scalar{&hiddenAttr}, Yh)
	if err != nil {
		t.Fatalf("PrepareBlindSign failed: %v", err)
	}
	if proof == nil || d == nil {
		t.Fatal("PrepareBlindSign returned nil proof or blinding factor")
	}

	publicAttrs := []*bls12381.Scalar{&publicAttr}
	blindSignature, err := lib.BlindSign(keys.SecretKey, keys.PublicKey, proof, publicAttrs)
	if err != nil {
		t.Fatalf("BlindSign failed: %v", err)
	}
	if blindSignature == nil {
		t.Fatal("BlindSign returned a nil signature")
	}

	finalSignature, err := lib.Unblind(blindSignature, d)
	if err != nil {
		t.Fatalf("Unblind failed: %v", err)
	}
	if finalSignature == nil {
		t.Fatal("Unblind returned a nil signature")
	}

	allAttributes := []*bls12381.Scalar{&publicAttr, &hiddenAttr}
	isValid := lib.PSVerify(finalSignature, allAttributes, keys.PublicKey)
	if !isValid {
		t.Fatal("The final, unblinded signature failed verification!")
	}
}

// TestAnonymousCredentialPresentation covers three behaviours of the presentation
// protocol: an honest presentation verifies, one checked against another issuer's
// key does not, and two presentations of the same credential both verify while
// differing byte-wise, which is the unlinkability the paper claims.
func TestAnonymousCredentialPresentation(t *testing.T) {
	keys := lib.PSKeyGen(1)
	var hidden bls12381.Scalar
	hidden.SetBytes([]byte("123456789"))
	attrs := []*bls12381.Scalar{&hidden}
	sig, err := lib.PSSign(attrs, keys.SecretKey)
	if err != nil {
		t.Fatalf("Setup: PSSign failed: %v", err)
	}

	present := func(label string) *lib.AnoyCredPresentation {
		t.Helper()
		rsig, _, tSig, err := lib.RandomizeSig(sig)
		if err != nil {
			t.Fatalf("%s: RandomizeSig: %v", label, err)
		}
		var ri bls12381.Scalar
		if err := ri.Random(rand.Reader); err != nil {
			t.Fatalf("%s: ri random: %v", label, err)
		}
		p, err := lib.AnoyCredPresent(rsig, tSig, attrs, []*bls12381.Scalar{&ri}, keys.PublicKey, nil)
		if err != nil {
			t.Fatalf("%s: AnoyCredPresent: %v", label, err)
		}
		if p == nil {
			t.Fatalf("%s: AnoyCredPresent returned nil", label)
		}
		ok, err := lib.VerifyAnoyCredPresent(p, keys.PublicKey)
		if err != nil || !ok {
			t.Fatalf("%s: presentation failed to verify (err=%v)", label, err)
		}
		return p
	}

	p1 := present("first")

	t.Run("completeness", func(t *testing.T) {
		ok, err := lib.VerifyAnoyCredPresent(p1, keys.PublicKey)
		if err != nil {
			t.Fatalf("VerifyAnoyCredPresent: %v", err)
		}
		if !ok {
			t.Fatal("honest presentation failed verification")
		}
	})

	t.Run("wrong_public_key_rejected", func(t *testing.T) {
		wrong := lib.PSKeyGen(1)
		if ok, _ := lib.VerifyAnoyCredPresent(p1, wrong.PublicKey); ok {
			t.Error("presentation verified under a different issuer's public key — soundness broken")
		}
	})

	t.Run("unlinkability", func(t *testing.T) {
		p2 := present("second")
		if p1.Sigma.Sigma1.IsEqual(p2.Sigma.Sigma1) && p1.Sigma.Sigma2.IsEqual(p2.Sigma.Sigma2) {
			t.Error("two presentations produced identical randomized Sigma — unlinkability broken")
		}
		if p1.C.IsEqual(p2.C) {
			t.Error("two presentations produced identical commitment C — randomness reused")
		}
	})
}
