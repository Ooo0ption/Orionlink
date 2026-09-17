// IdP side of the AAKA exchange: PoK verification, AUID generation, X3DH session
// key derivation, and token issuance.
package idp

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
)

// handleToken is the IdP's token endpoint for the AAKA flow: it verifies the
// RP's PoK, checks that the proof's acid matches the one the user consented to,
// derives K_S, and returns the blinded auid together with the issued tokens.
func (s *IdPServer) handleToken(c *fiber.Ctx) error {
	req := &protocol.AAKETokenRequest{}
	if err := s.getRequest(c, req); err != nil {
		return s.handleError(c, comm.BadRequest, "invalid request body"+err.Error())
	}
	code := req.Code
	codeData, err := s.store.codes.GetCode(code)
	if err != nil {
		return s.handleError(c, comm.Unauthorized, "invalid code"+err.Error())
	}
	proof, err := toProof(req)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "invalid proof"+err.Error())
	}
	if ok, err := verifyPoK(s, proof); !ok {
		return s.handleError(c, comm.Unauthorized, "invalid proof"+err.Error())
	}
	var consentACID struct {
		Sigma1 string
		Sigma2 string
	}
	if err := json.Unmarshal([]byte(codeData.ACID), &consentACID); err != nil {
		return s.handleError(c, comm.BadRequest, "malformed consent acid: "+err.Error())
	}
	if comm.G1ToString(proof.Sign1.Sigma1) != consentACID.Sigma1 ||
		comm.G1ToString(proof.Sign1.Sigma2) != consentACID.Sigma2 {
		return s.handleError(c, comm.Unauthorized, "acid mismatch: consent credential != issuance credential")
	}
	edata, err := toE2eeData(req)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "invalid e2ee data"+err.Error())
	}
	sessionKey, err := getSessionKey(s, edata)
	if err != nil {
		return s.handleError(c, comm.Unauthorized, "invalid session key"+err.Error())
	}
	if err := saveSessionKS(sessionKey); err != nil {
		log.Printf("[WARN/IdP] failed to persist K_S for refresh ratchet: %v", err)
	}
	uid := lib.HashStringToScalar(codeData.UID)
	auid := GenerateAuid(proof.Sign1.Sigma1, uid)
	auidStr := comm.G1ToString(auid)
	log.Printf("[INFO/IdP] AAKA proof verified; derived blinded per-RP user pseudonym auid = BlindEval(uid, acid)")

	userData := &authorizedUserData{
		acid:     codeData.ACID,
		auid:     auidStr,
		uid:      codeData.UID,
		OprfEnc:  codeData.OprfEnc,
		username: codeData.Username,
		email:    codeData.Email,
		scope:    codeData.Scope,
	}
	idToken, accessToken, refreshToken, err := generateTokens(s, userData, sessionKey)
	if err != nil {
		return s.handleError(c, comm.ServerError, "failed to generate tokens"+err.Error())
	}
	userData.IdToken = idToken
	userData.AccessToken = accessToken
	userData.RefreshToken = refreshToken
	log.Printf("[INFO/IdP] Issued id/access tokens; identity claims (sub/name/email/scope) encrypted under K_S — broker sees only ciphertext")
	s.store.authorized_msgs.Add(userData)

	s.store.codes.DeleteCode(code)

	resp := protocol.AAKETokenResponse{
		AUID:         auidStr,
		IdToken:      idToken,
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
	}
	return c.JSON(resp)
}

// verifyPoK checks the RP's Σ-protocol proof of knowledge of its credentials:
// it recomputes the Fiat-Shamir challenge, verifies the three response equations,
// and pairing-checks both PS signatures against the IdP's verification keys.
func verifyPoK(s *IdPServer, proof *proofPoK) (bool, error) {
	hsh := sha256.New()
	for _, y := range s.CredKey.PSKey1.PublicKey.Yhatn {
		hsh.Write(y.BytesCompressed())
	}
	for _, y := range s.CredKey.PSKey2.PublicKey.Yhatn {
		hsh.Write(y.BytesCompressed())
	}
	hsh.Write(proof.C1.BytesCompressed())
	hsh.Write(proof.C2.BytesCompressed())
	hsh.Write(proof.C3.BytesCompressed())
	hsh.Write(proof.R1.BytesCompressed())
	hsh.Write(proof.R2.BytesCompressed())
	hsh.Write(proof.R3.BytesCompressed())

	var c bls12381.Scalar
	c.SetBytes(hsh.Sum(nil))

	zD, zQsk := proof.ZD, proof.ZQsk
	z1, z2, z3 := proof.Z1, proof.Z2, proof.Z3

	var left1, right1 bls12381.G2
	var tmpG2 bls12381.G2
	left1.ScalarMult(z1, bls12381.G2Generator())
	tmpG2.ScalarMult(zD, s.CredKey.PSKey1.PublicKey.Yhatn[0])
	left1.Add(&left1, &tmpG2)
	right1 = *proof.R1
	tmpG2.ScalarMult(&c, proof.C1)
	right1.Add(&right1, &tmpG2)
	if !left1.IsEqual(&right1) {
		return false, errors.New("verification of proof component 1 failed")
	}

	var left2, right2 bls12381.G2
	left2.ScalarMult(z2, bls12381.G2Generator())
	tmpG2.ScalarMult(zD, s.CredKey.PSKey2.PublicKey.Yhatn[0])
	left2.Add(&left2, &tmpG2)
	tmpG2.ScalarMult(zQsk, s.CredKey.PSKey2.PublicKey.Yhatn[1])
	left2.Add(&left2, &tmpG2)
	right2 = *proof.R2
	tmpG2.ScalarMult(&c, proof.C2)
	right2.Add(&right2, &tmpG2)
	if !left2.IsEqual(&right2) {
		return false, errors.New("verification of proof component 2 failed")
	}

	var left3, right3 bls12381.G1
	left3.ScalarMult(z3, bls12381.G1Generator())
	right3 = *proof.R3
	var tmpG1 bls12381.G1
	tmpG1.ScalarMult(&c, proof.C3)
	right3.Add(&right3, &tmpG1)
	if !left3.IsEqual(&right3) {
		return false, errors.New("verification of proof component 3 failed")
	}

	var lhs, rhs bls12381.Gt
	var sumG2 bls12381.G2
	sumG2.Add(proof.C1, s.CredKey.PSKey1.PublicKey.Xhat)
	lhs = *bls12381.Pair(proof.Sign1.Sigma1, &sumG2)
	rhs = *bls12381.Pair(proof.Sign1.Sigma2, bls12381.G2Generator())
	if !lhs.IsEqual(&rhs) {
		return false, errors.New("verification of PS signature 1 failed")
	}

	sumG2.Add(proof.C2, s.CredKey.PSKey2.PublicKey.Xhat)
	lhs = *bls12381.Pair(proof.Sign2.Sigma1, &sumG2)
	rhs = *bls12381.Pair(proof.Sign2.Sigma2, bls12381.G2Generator())
	if !lhs.IsEqual(&rhs) {
		return false, errors.New("verification of PS signature 2 failed")
	}

	return true, nil
}

// GenerateAuid derives the blinded anonymous user ID acid^uid for the RP.
func GenerateAuid(acid *bls12381.G1, uid *bls12381.Scalar) *bls12381.G1 {
	var blindAuid bls12381.G1
	blindAuid.ScalarMult(uid, acid)
	return &blindAuid
}

// proofPoK is the decoded AAKA proof: the two randomized PS signatures, the
// commitments C*, the challenge announcements R*, and the responses Z*.
type proofPoK struct {
	Sign1 *lib.PSSignMsg
	Sign2 *lib.PSSignMsg
	C1    *bls12381.G2
	C2    *bls12381.G2
	C3    *bls12381.G1
	R1    *bls12381.G2
	R2    *bls12381.G2
	R3    *bls12381.G1
	ZD    *bls12381.Scalar
	ZQsk  *bls12381.Scalar
	Z1    *bls12381.Scalar
	Z2    *bls12381.Scalar
	Z3    *bls12381.Scalar
}

// toProof decodes the wire form of a token request into a proofPoK.
func toProof(req *protocol.AAKETokenRequest) (proof *proofPoK, err error) {
	sign1 := &lib.PSSignMsg{}
	if err := sign1.FromJSON(req.Sign1); err != nil {
		return nil, errors.New("invalid sign1: " + err.Error())
	}
	sign2 := &lib.PSSignMsg{}
	if err := sign2.FromJSON(req.Sign2); err != nil {
		return nil, errors.New("invalid sign2: " + err.Error())
	}
	proof = &proofPoK{
		Sign1: sign1,
		Sign2: sign2,
	}
	proof.C1, _ = comm.BytesToG2(req.C.C1)
	proof.C2, _ = comm.BytesToG2(req.C.C2)
	proof.C3, _ = comm.BytesToG1(req.C.C3)
	proof.R1, _ = comm.BytesToG2(req.R.R1)
	proof.R2, _ = comm.BytesToG2(req.R.R2)
	proof.R3, _ = comm.BytesToG1(req.R.R3)
	proof.ZD, _ = comm.BytesToScalar(req.Z.ZD)
	proof.ZQsk, _ = comm.BytesToScalar(req.Z.ZQsk)
	proof.Z1, _ = comm.BytesToScalar(req.Z.Z1)
	proof.Z2, _ = comm.BytesToScalar(req.Z.Z2)
	proof.Z3, _ = comm.BytesToScalar(req.Z.Z3)

	return proof, nil
}

// e2eeData is the RP's X3DH material: its identity and ephemeral public keys,
// the id of the IdP ephemeral key it used, and the key-confirmation ciphertext.
type e2eeData struct {
	ClientPK    *bls12381.G1
	ClientEmpPK *bls12381.G1
	IdPEmpKeyId string
	Msg         []byte
}

// toE2eeData decodes the X3DH section of a token request.
func toE2eeData(req *protocol.AAKETokenRequest) (e2ee *e2eeData, err error) {
	e2ee = &e2eeData{}
	e2ee.ClientPK, err = comm.BytesToG1(req.E2EE.ClientPK)
	if err != nil {
		return nil, err
	}
	e2ee.ClientEmpPK, err = comm.BytesToG1(req.E2EE.ClientEmpPK)
	if err != nil {
		return nil, err
	}
	e2ee.IdPEmpKeyId = req.E2EE.IdPEmpKeyId
	e2ee.Msg = req.E2EE.Msg
	return e2ee, nil
}

// x3KeyExchangeIdP computes the three X3DH shared secrets from the IdP's side,
// pairing its identity and ephemeral keys against the RP's.
func x3KeyExchangeIdP(sk1 *bls12381.Scalar, sk2 *bls12381.Scalar, pk1 *bls12381.G1, pk2 *bls12381.G1) (dh1, dh2, dh3 []byte, err error) {
	if sk1 == nil || pk1 == nil || sk2 == nil || pk2 == nil {
		return nil, nil, nil, errors.New("sk or pk is nil")
	}
	dh1, err = lib.DH(sk2, pk1)
	if err != nil {
		return nil, nil, nil, err
	}
	dh2, err = lib.DH(sk1, pk2)
	if err != nil {
		return nil, nil, nil, err
	}
	dh3, err = lib.DH(sk2, pk2)
	if err != nil {
		return nil, nil, nil, err
	}

	return dh1, dh2, dh3, nil
}

// getSessionKey derives the AAKA session key K_S from the RP's X3DH material.
func getSessionKey(s *IdPServer, e2ee *e2eeData) (Ks []byte, err error) {
	serverEmpKey, err := s.store.empkeys.getEmpKey(e2ee.IdPEmpKeyId)
	if err != nil {
		return nil, errors.New("failed to get server empheral key")
	}
	dh1, dh2, dh3, err := x3KeyExchangeIdP(s.IdentityKey.SK, serverEmpKey.SK, e2ee.ClientPK, e2ee.ClientEmpPK)
	if err != nil {
		return nil, errors.New("failed to exchange keys")
	}
	tempSessionKey, err := lib.DeriveSessionKey(dh1, dh2, dh3)
	if err != nil {
		return nil, errors.New("failed to derive session key")
	}
	aad := append(e2ee.ClientPK.BytesCompressed(), s.IdentityKey.PK.BytesCompressed()...)
	msgDec, err := lib.AesGcmDecrypt(tempSessionKey, e2ee.Msg, aad)
	if err != nil {
		return nil, errors.New("failed to decrypt msg")
	}
	msg := append(e2ee.ClientEmpPK.BytesCompressed(), serverEmpKey.PK.BytesCompressed()...)
	if !bytes.Equal(msg, msgDec) {
		return nil, errors.New("failed to decrypt msg")
	}

	return tempSessionKey, nil
}

// generateTokens issues the JWTs returned to the broker. Every user-attribute
// value (sub/uid, name, email, scope) is AES-GCM encrypted under the AAKA
// session key K_S; the envelope claims (iss, aud=acid, exp, iat, kid) stay
// plaintext so the broker can route and re-sign without seeing user data. Only
// the RP, which derives the same K_S, can decrypt.
func generateTokens(s *IdPServer, data *authorizedUserData, Ks []byte) (idToken, accessToken, refreshToken string, err error) {
	encUid, err := lib.AESEncryptString(Ks, data.uid)
	if err != nil {
		return "", "", "", err
	}
	encUsername, err := lib.AESEncryptString(Ks, data.username)
	if err != nil {
		return "", "", "", err
	}
	encEmail, err := lib.AESEncryptString(Ks, data.email)
	if err != nil {
		return "", "", "", err
	}
	encScope, err := lib.AESEncryptString(Ks, data.scope)
	if err != nil {
		return "", "", "", err
	}

	idToken, err = s.tokenHelper.GenerateIDToken(encUid, encUsername, encEmail, data.acid)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to generate ID Token: %v", err)
		return "", "", "", err
	}

	accessToken, err = s.tokenHelper.GenerateAccessToken(encUid, encScope, data.acid)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to generate Access Token: %v", err)
		return "", "", "", err
	}

	refreshToken, err = s.tokenHelper.GenerateRefreshToken(data.uid, data.scope, data.acid)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to generate Refresh Token: %v", err)
		return "", "", "", err
	}

	return idToken, accessToken, refreshToken, nil
}
