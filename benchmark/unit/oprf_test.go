// Unit test for the PIN-OPRF round trip between client and server.
package unit

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"

	"secure-sso/lib/oprf"
)

func TestOPRFRoundTripAndConsistency(t *testing.T) {
	server := oprf.NewPinHelper()
	g := server.Group

	const input = "user-pin-123456"

	ref := g.NewElement()
	ref.Mul(g.HashToElement([]byte(input), nil), server.Skey)
	refBytes, err := ref.MarshalBinary()
	if err != nil {
		t.Fatalf("ref marshal: %v", err)
	}

	runOne := func() []byte {
		t.Helper()
		P := g.HashToElement([]byte(input), nil)
		r := g.RandomScalar(rand.Reader)
		B := g.NewElement()
		B.Mul(P, r)
		bBytes, err := B.MarshalBinary()
		if err != nil {
			t.Fatalf("B marshal: %v", err)
		}

		zBytes, err := server.ServerEvaluate(bBytes)
		if err != nil {
			t.Fatalf("ServerEvaluate: %v", err)
		}

		Z := g.NewElement()
		if err := Z.UnmarshalBinary(zBytes); err != nil {
			t.Fatalf("Z unmarshal: %v", err)
		}
		rInv := g.NewScalar()
		rInv.Inv(r)
		out := g.NewElement()
		out.Mul(Z, rInv)
		outBytes, err := out.MarshalBinary()
		if err != nil {
			t.Fatalf("out marshal: %v", err)
		}
		return outBytes
	}

	t.Run("round-trip recovers H(input)·k", func(t *testing.T) {
		got := runOne()
		if !bytes.Equal(got, refBytes) {
			t.Errorf("OPRF output != H(input)·k\n  got = %x\n  ref = %x", got, refBytes)
		}
	})

	t.Run("consistency: two independent r values yield same OPRF output", func(t *testing.T) {
		first := runOne()
		second := runOne()
		if !bytes.Equal(first, second) {
			t.Errorf("OPRF non-deterministic across blinding factors\n  r1 -> %x\n  r2 -> %x", first, second)
		}
	})

	t.Run("changing server key changes the output", func(t *testing.T) {
		other := oprf.NewPinHelper()
		P := g.HashToElement([]byte(input), nil)
		r := g.RandomScalar(rand.Reader)
		B := g.NewElement()
		B.Mul(P, r)
		bBytes, _ := B.MarshalBinary()
		zBytes, err := other.ServerEvaluate(bBytes)
		if err != nil {
			t.Fatalf("other.ServerEvaluate: %v", err)
		}
		Z := g.NewElement()
		_ = Z.UnmarshalBinary(zBytes)
		rInv := g.NewScalar()
		rInv.Inv(r)
		out := g.NewElement()
		out.Mul(Z, rInv)
		outBytes, _ := out.MarshalBinary()
		if bytes.Equal(outBytes, refBytes) {
			t.Errorf("OPRF collision between two distinct server keys — extremely unlikely unless implementation degenerated")
		}
	})

	_ = group.Ristretto255
}
