// Unit tests for the PS signature scheme and its wire encoding.
package unit

import (
	"secure-sso/lib"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// TestPSSignature walks the full PS signature lifecycle: key generation, signing,
// verification, rejection of wrong attributes, randomization, verification of the
// randomized signature, and rejection of cross-verification.
func TestPSSignature(t *testing.T) {
	const numAttributes = 2
	keys := lib.PSKeyGen(numAttributes)
	if keys == nil || keys.SecretKey == nil || keys.PublicKey == nil {
		t.Fatal("KeyGen failed to produce valid keys")
	}
	if len(keys.SecretKey.GetSecretY()) != numAttributes || len(keys.PublicKey.Yn) != numAttributes {
		t.Fatalf("KeyGen did not generate the correct number of attribute keys, expected %d", numAttributes)
	}

	var attr1, attr2 bls12381.Scalar
	attr1.SetBytes([]byte("12345"))
	attr2.SetBytes([]byte("56789"))
	attributes := []*bls12381.Scalar{&attr1, &attr2}

	signature, err := lib.PSSign(attributes, keys.SecretKey)
	if err != nil {
		t.Fatalf("Sign() returned an error: %v", err)
	}
	if signature == nil || signature.Sigma1 == nil || signature.Sigma2 == nil {
		t.Fatal("Sign() returned a nil signature")
	}

	isValid := lib.PSVerify(signature, attributes, keys.PublicKey)
	if !isValid {
		t.Fatal("Verify() failed for a valid signature and attributes")
	}

	var wrongAttr bls12381.Scalar
	wrongAttr.SetBytes([]byte("99999"))
	wrongAttributes := []*bls12381.Scalar{&attr1, &wrongAttr}
	isWrongValid := lib.PSVerify(signature, wrongAttributes, keys.PublicKey)
	if isWrongValid {
		t.Fatal("PSVerify() succeeded for incorrect attributes, but should have failed")
	}

	randSignature, k, randT, err := lib.RandomizeSig(signature)
	if err != nil {
		t.Fatalf("Randomize() returned an error: %v", err)
	}
	if randSignature == nil || k == nil || randT == nil {
		t.Fatal("Randomize() returned nil values")
	}

	isRandValid := lib.VerifyRandomizedSig(randSignature, randT, attributes, keys.PublicKey)
	if !isRandValid {
		t.Fatal("VerifyRandomized() failed for a valid randomized signature")
	}

	if lib.PSVerify(randSignature, attributes, keys.PublicKey) {
		t.Error("A randomized signature should not be verifiable with the standard Verify() function")
	}

	if lib.VerifyRandomizedSig(signature, randT, attributes, keys.PublicKey) {
		t.Error("A standard signature should not be verifiable with VerifyRandomized()")
	}

	var wrongT bls12381.Scalar
	wrongT.SetBytes([]byte("99999"))
	if lib.VerifyRandomizedSig(randSignature, &wrongT, attributes, keys.PublicKey) {
		t.Error("VerifyRandomized() succeeded with an incorrect 't' value")
	}
}

// TestPSSignMsgJSONRoundTrip guards the flat ToJSON/FromJSON encoding the wire
// layer depends on, so a break in G1 recovery fails here rather than in a browser
// login test.
func TestPSSignMsgJSONRoundTrip(t *testing.T) {
	keys := lib.PSKeyGen(2)
	var a1, a2 bls12381.Scalar
	a1.SetBytes([]byte("attr-one"))
	a2.SetBytes([]byte("attr-two"))
	sig, err := lib.PSSign([]*bls12381.Scalar{&a1, &a2}, keys.SecretKey)
	if err != nil {
		t.Fatalf("PSSign: %v", err)
	}
	rsig, _, _, err := lib.RandomizeSig(sig)
	if err != nil {
		t.Fatalf("RandomizeSig: %v", err)
	}

	raw, err := rsig.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if got, want := len(raw), 2*bls12381.G1SizeCompressed; got != want {
		t.Errorf("ToJSON byte length = %d, want %d (= 2 * G1 compressed)", got, want)
	}

	restored := &lib.PSSignMsg{}
	if err := restored.FromJSON(raw); err != nil {
		t.Fatalf("FromJSON: %v", err)
	}
	if !restored.Sigma1.IsEqual(rsig.Sigma1) {
		t.Errorf("restored.Sigma1 != original.Sigma1")
	}
	if !restored.Sigma2.IsEqual(rsig.Sigma2) {
		t.Errorf("restored.Sigma2 != original.Sigma2")
	}

	rsigForT, _, tRand, err := lib.RandomizeSig(sig)
	if err != nil {
		t.Fatalf("RandomizeSig#2: %v", err)
	}
	rawT, _ := rsigForT.ToJSON()
	restoredT := &lib.PSSignMsg{}
	if err := restoredT.FromJSON(rawT); err != nil {
		t.Fatalf("FromJSON#2: %v", err)
	}
	if !lib.VerifyRandomizedSig(restoredT, tRand,
		[]*bls12381.Scalar{&a1, &a2}, keys.PublicKey) {
		t.Error("restored randomized sig failed VerifyRandomizedSig — G1 points were not preserved")
	}
}
