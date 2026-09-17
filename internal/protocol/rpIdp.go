// Wire messages of the RP to IdP exchanges: key publication and registration.
package protocol

import (
	"errors"
	comm "secure-sso/internal/common"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// IdPCredKeyResponse carries the IdP's credential verification keys, served at
// /ssso/pubkeys so the RP can verify PS signatures: VK1 for the DC, VK2 for the SC.
type IdPCredKeyResponse struct {
	VK1    PSPublicKeyResponse `json:"vk1"`
	VK2    PSPublicKeyResponse `json:"vk2"`
	AAKEPk []byte              `json:"aake_pk,omitempty"`
}

// FromJson decodes the wire form of both verification keys into PSPublicKeys,
// rejecting a VK1 that is not 1-message or a VK2 that is not 2-message.
func (p *IdPCredKeyResponse) FromJson() (vk1 *lib.PSPublicKey, vk2 *lib.PSPublicKey, err error) {
	vk1 = &lib.PSPublicKey{}
	vk2 = &lib.PSPublicKey{}
	if len(p.VK1.Yn) != 1 {
		return nil, nil, errors.New("Invalid Vk1 Yn length")
	}
	Yn0, _ := comm.BytesToG1(p.VK1.Yn[0])
	vk1.Yn = []*bls12381.G1{Yn0}
	vk1.Xhat, _ = comm.BytesToG2(p.VK1.Xhat)
	Yhatn0, _ := comm.BytesToG2(p.VK1.Yhatn[0])
	vk1.Yhatn = []*bls12381.G2{Yhatn0}
	if len(p.VK2.Yn) != 2 {
		return nil, nil, errors.New("Invalid Vk2")
	}
	Yn1, _ := comm.BytesToG1(p.VK2.Yn[0])
	Yn2, _ := comm.BytesToG1(p.VK2.Yn[1])
	vk2.Yn = []*bls12381.G1{Yn1, Yn2}
	vk2.Xhat, _ = comm.BytesToG2(p.VK2.Xhat)
	Yhatn1, _ := comm.BytesToG2(p.VK2.Yhatn[0])
	Yhatn2, _ := comm.BytesToG2(p.VK2.Yhatn[1])
	vk2.Yhatn = []*bls12381.G2{Yhatn1, Yhatn2}

	return vk1, vk2, nil
}

// PSPublicKeyResponse is the wire form of one PS verification key.
type PSPublicKeyResponse struct {
	Yn    [][]byte `json:"yn"`
	Xhat  []byte   `json:"xhat"`
	Yhatn [][]byte `json:"yhatn"`
}

// IdPEmpKeyResponse carries an IdP ephemeral DH public key for the X3DH step,
// with KID identifying which key so the IdP can recover the matching secret.
type IdPEmpKeyResponse struct {
	KID string `json:"kid"`
	PK  []byte `json:"pk"`
}

// RPRegisterToIdPRequest is the Phase-1 RP to IdP register message, paper's
// (D, pi_1): the domain plus the NIZK proving knowledge of d and rsk_IK.
type RPRegisterToIdPRequest struct {
	Domain []byte   `json:"domain"`
	C1     []byte   `json:"c1"`
	R1     []byte   `json:"r1"`
	Z0     []byte   `json:"z0"`
	Zs     [][]byte `json:"zs"`
}

// RPRegisterToIdPResponse is the Phase-1 IdP to RP response: Sig1 is the PS
// signature on D, BlindSig2 the blinded signature on (D, rsk_IK) that the RP
// unblinds into sigma_bar.
type RPRegisterToIdPResponse struct {
	Sig1      []byte `json:"sig1"`
	BlindSig2 []byte `json:"blindSig2"`
}
