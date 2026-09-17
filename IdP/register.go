// IdP handling of RP registration: credential issuance in response to the RP's
// register request.
package idp

import (
	"errors"
	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// getRegisterRespToRP verifies the RP's registration proof and issues its
// DomainCred plus the blinded SecretCred signature.
func getRegisterRespToRP(s *IdPServer, req *protocol.RPRegisterToIdPRequest) (resp *protocol.RPRegisterToIdPResponse, err error) {
	if req == nil {
		return nil, errors.New("invalid input to IDPRegistrationReq: request is nil")
	}

	if s.CredKey == nil || s.CredKey.PSKey1 == nil || s.CredKey.PSKey2 == nil {
		return nil, errors.New("credential keys not initialized")
	}
	if s.CredKey.PSKey1.SecretKey == nil || s.CredKey.PSKey2.SecretKey == nil {
		return nil, errors.New("credential secret keys not initialized")
	}

	var domainScalar bls12381.Scalar
	domainScalar.SetBytes(req.Domain)
	sig1, err := lib.PSSign([]*bls12381.Scalar{&domainScalar}, s.CredKey.PSKey1.SecretKey)
	if err != nil {
		return nil, errors.New("PSSign failed: " + err.Error())
	}
	if sig1 == nil {
		return nil, errors.New("PSSign returned nil signature")
	}

	c1, _ := comm.BytesToG1(req.C1)
	r1, _ := comm.BytesToG1(req.R1)
	z0, _ := comm.BytesToScalar(req.Z0)
	zs := make([]*bls12381.Scalar, len(req.Zs))
	for i, z := range req.Zs {
		zs[i], _ = comm.BytesToScalar(z)
	}
	proof := &lib.MultiExpProof{
		C1: c1,
		R1: r1,
		Z0: z0,
		Zs: zs,
	}
	sig2, err := lib.BlindSign(s.CredKey.PSKey2.SecretKey, s.CredKey.PSKey2.PublicKey, proof, []*bls12381.Scalar{&domainScalar})
	if err != nil {
		return nil, errors.New("BlindSign failed: " + err.Error())
	}
	if sig2 == nil {
		return nil, errors.New("BlindSign returned nil signature")
	}
	sigByte1, err := sig1.ToJSON()
	if err != nil {
		return nil, errors.New("failed to marshal sig1: " + err.Error())
	}
	sigByte2, err := sig2.ToJSON()
	if err != nil {
		return nil, errors.New("failed to marshal sig2: " + err.Error())
	}
	resp = &protocol.RPRegisterToIdPResponse{
		Sig1:      sigByte1,
		BlindSig2: sigByte2,
	}
	return resp, nil
}
