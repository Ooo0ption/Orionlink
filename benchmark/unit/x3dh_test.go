// Unit test that both sides of the X3DH exchange derive the same session key.
package unit

import (
	"bytes"
	"testing"

	"secure-sso/lib"
)

func TestX3DHSymmetric(t *testing.T) {
	rskIK, rpkIK := lib.GenerateEmpKey()
	rskE, rpkE := lib.GenerateEmpKey()
	iskIK, ipkIK := lib.GenerateEmpKey()
	iskE, ipkE := lib.GenerateEmpKey()

	dh1RP, err := lib.DH(rskIK, ipkE)
	if err != nil {
		t.Fatalf("RP dh1: %v", err)
	}
	dh2RP, err := lib.DH(rskE, ipkIK)
	if err != nil {
		t.Fatalf("RP dh2: %v", err)
	}
	dh3RP, err := lib.DH(rskE, ipkE)
	if err != nil {
		t.Fatalf("RP dh3: %v", err)
	}

	dh1IdP, err := lib.DH(iskE, rpkIK)
	if err != nil {
		t.Fatalf("IdP dh1: %v", err)
	}
	dh2IdP, err := lib.DH(iskIK, rpkE)
	if err != nil {
		t.Fatalf("IdP dh2: %v", err)
	}
	dh3IdP, err := lib.DH(iskE, rpkE)
	if err != nil {
		t.Fatalf("IdP dh3: %v", err)
	}

	if !bytes.Equal(dh1RP, dh1IdP) {
		t.Errorf("dh1 mismatch: rp=%x idp=%x", dh1RP, dh1IdP)
	}
	if !bytes.Equal(dh2RP, dh2IdP) {
		t.Errorf("dh2 mismatch: rp=%x idp=%x", dh2RP, dh2IdP)
	}
	if !bytes.Equal(dh3RP, dh3IdP) {
		t.Errorf("dh3 mismatch: rp=%x idp=%x", dh3RP, dh3IdP)
	}

	KsRP, err := lib.DeriveSessionKey(dh1RP, dh2RP, dh3RP)
	if err != nil {
		t.Fatalf("DeriveSessionKey RP: %v", err)
	}
	KsIdP, err := lib.DeriveSessionKey(dh1IdP, dh2IdP, dh3IdP)
	if err != nil {
		t.Fatalf("DeriveSessionKey IdP: %v", err)
	}
	if !bytes.Equal(KsRP, KsIdP) {
		t.Errorf("K_S mismatch:\n  RP  = %x\n  IdP = %x", KsRP, KsIdP)
	}
	if len(KsRP) == 0 {
		t.Errorf("K_S unexpectedly empty")
	}
}
