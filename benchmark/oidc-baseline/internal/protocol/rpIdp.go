package protocol

import (
	"errors"
	"secure-sso/lib"
	comm "secure-sso/internal/common"

	"github.com/cloudflare/circl/ecc/bls12381"
)

type IdPCredKeyResponse struct {
	VK1 PSPublicKeyResponse `json:"vk1"`
	VK2 PSPublicKeyResponse `json:"vk2"`
}

func (p *IdPCredKeyResponse) FromJson() (vk1 *lib.PSPublicKey, vk2 *lib.PSPublicKey, err error) {
	vk1 = &lib.PSPublicKey{}
	vk2 = &lib.PSPublicKey{}
	//vk1
	if len(p.VK1.Yn) != 1 {
		return nil, nil, errors.New("Invalid Vk1 Yn length")
	}
	Yn0, _ := comm.BytesToG1(p.VK1.Yn[0])
	vk1.Yn = []*bls12381.G1{Yn0}
	vk1.Xhat, _ = comm.BytesToG2(p.VK1.Xhat)
	Yhatn0, _ := comm.BytesToG2(p.VK1.Yhatn[0])
	vk1.Yhatn = []*bls12381.G2{Yhatn0}
	//vk2
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

type PSPublicKeyResponse struct {
	Yn    [][]byte `json:"yn"`
	Xhat  []byte   `json:"xhat"`
	Yhatn [][]byte `json:"yhatn"`
}

type IdPEmpKeyResponse struct {
	KID string `json:"kid"`
	PK  []byte `json:"pk"`
}
type RPRegisterToIdPRequest struct {
	Domain []byte   `json:"domain"`
	C1     []byte   `json:"c1"`
	R1     []byte   `json:"r1"`
	Z0     []byte   `json:"z0"`
	Zs     [][]byte `json:"zs"`
}

type RPRegisterToIdPResponse struct {
	Sig1      []byte `json:"sig1"`
	BlindSig2 []byte `json:"blindSig2"`
}
