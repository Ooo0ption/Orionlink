// Unit test that AAKA wire messages survive a JSON round trip.
package unit

import (
	"encoding/json"
	"testing"

	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// realisticPSSign returns a flat signature blob in the shape that flows on the wire.
func realisticPSSign(t *testing.T) []byte {
	t.Helper()
	keys := lib.PSKeyGen(2)
	var a1, a2 bls12381.Scalar
	a1.SetBytes([]byte("attr1"))
	a2.SetBytes([]byte("attr2"))
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
	return raw
}

// assertEqBytes compares two byte slices and names the field on mismatch.
func assertEqBytes(t *testing.T, got, want []byte, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: length mismatch got=%d want=%d", what, len(got), len(want))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: byte %d mismatch got=%x want=%x", what, i, got[i], want[i])
			return
		}
	}
}

func TestAAKEWireRoundTrip(t *testing.T) {
	sign1 := realisticPSSign(t)
	sign2 := realisticPSSign(t)
	rsig1 := realisticPSSign(t)

	t.Run("AAKETokenRequest", func(t *testing.T) {
		orig := protocol.AAKETokenRequest{
			Sign1: sign1,
			Sign2: sign2,
			C:     protocol.CGroup{C1: []byte("c1"), C2: []byte("c2"), C3: []byte("c3")},
			R:     protocol.RGroup{R1: []byte("r1"), R2: []byte("r2"), R3: []byte("r3")},
			Z:     protocol.ZGroup{ZD: []byte("zd"), ZQsk: []byte("zqsk"), Z1: []byte("z1"), Z2: []byte("z2"), Z3: []byte("z3")},
			E2EE:  protocol.E2EE{ClientPK: []byte("cpk"), ClientEmpPK: []byte("ceK"), IdPEmpKeyId: "0", Msg: []byte("m")},
			Code:  "the-code",
		}
		bytes, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var dec protocol.AAKETokenRequest
		if err := json.Unmarshal(bytes, &dec); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		assertEqBytes(t, dec.Sign1, orig.Sign1, "Sign1")
		assertEqBytes(t, dec.Sign2, orig.Sign2, "Sign2")
		if dec.Code != orig.Code {
			t.Errorf("Code: got %q want %q", dec.Code, orig.Code)
		}
		ps := &lib.PSSignMsg{}
		if err := ps.FromJSON(dec.Sign1); err != nil {
			t.Fatalf("PSSignMsg.FromJSON on round-tripped Sign1: %v", err)
		}
		if ps.Sigma1 == nil || ps.Sigma2 == nil {
			t.Fatal("recovered PSSignMsg has nil G1 points")
		}
	})

	t.Run("AAKEGenPoKResponse", func(t *testing.T) {
		orig := protocol.AAKEGenPoKResponse{
			Sign1: sign1,
			Sign2: sign2,
			C:     protocol.CGroup{C1: []byte("c1")},
		}
		bytes, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var dec protocol.AAKEGenPoKResponse
		if err := json.Unmarshal(bytes, &dec); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		assertEqBytes(t, dec.Sign1, orig.Sign1, "Sign1")
		assertEqBytes(t, dec.Sign2, orig.Sign2, "Sign2")
	})

	t.Run("AAKEGenPoKRequest", func(t *testing.T) {
		orig := protocol.AAKEGenPoKRequest{
			RSig1: rsig1,
			T:     []byte("t-bytes"),
			State: "state-xyz",
		}
		bytes, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var dec protocol.AAKEGenPoKRequest
		if err := json.Unmarshal(bytes, &dec); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		assertEqBytes(t, dec.RSig1, orig.RSig1, "RSig1")
		assertEqBytes(t, dec.T, orig.T, "T")
		if dec.State != orig.State {
			t.Errorf("State: got %q want %q", dec.State, orig.State)
		}
		ps := &lib.PSSignMsg{}
		if err := ps.FromJSON(dec.RSig1); err != nil {
			t.Fatalf("PSSignMsg.FromJSON on RSig1: %v", err)
		}
	})
}
