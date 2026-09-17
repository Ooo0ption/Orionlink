// RP side of the AAKA exchange: builds the credential proof, unblinds the AUID,
// and redeems the authorization code for tokens.
package rp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
)

// handleAAKEGenPoK answers the broker's PoK request: it proves knowledge of the
// RP's credentials against the randomized signature, attaches the X3DH material,
// and remembers the derived K_S for this login's state.
func (s *RPServer) handleAAKEGenPoK(c *fiber.Ctx) error {
	req := protocol.AAKEGenPoKRequest{}
	if err := c.BodyParser(&req); err != nil {
		return s.handleError(c, comm.BadRequest, "failed to parse request body"+err.Error())
	}
	resp, clientSk, clientPk, err := geneatePoK(s, &req)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "failed to generate AAKE PoK"+err.Error())
	}

	Ks, err := attachE2EE(s, c.Context(), resp, clientSk, clientPk)
	if err != nil {
		return s.handleError(c, comm.BadRequest, err.Error())
	}
	if err := saveSessionKS(Ks); err != nil {
		log.Printf("[WARN/RP] failed to persist K_S for refresh ratchet: %v", err)
	}

	state := req.State
	s.store.aakeStates.Save(state, &TempAAKEState{Ks: Ks})

	c.Status(fiber.StatusOK)
	return c.JSON(resp)
}

// attachE2EE fills in M's E2EE half: it takes an IdP ephemeral key, runs X3DH
// against it and writes (clientPk, clientEmpPk, kid, msg) into resp, returning
// the derived K_S. Persisting K_S and remembering the session are the caller's
// business — the load-test fixture endpoint does neither.
func attachE2EE(s *RPServer, ctx context.Context, resp *protocol.AAKEGenPoKResponse,
	clientSk *bls12381.Scalar, clientPk *bls12381.G1) ([]byte, error) {

	serverEmpResp := protocol.IdPEmpKeyResponse{}
	if err := s.sendGetRequest(ctx, s.config.EmpKeyURL, &serverEmpResp, http.StatusOK); err != nil {
		return nil, fmt.Errorf("failed to get server emp key%s", err.Error())
	}
	serverEmpPk, err := comm.BytesToG1(serverEmpResp.PK)
	if err != nil {
		return nil, fmt.Errorf("failed to get server emp key%s", err.Error())
	}
	Ks, clientEmpPk, msgEnc, err := newSession(clientSk, clientPk, s.IdPAAKEPk, serverEmpPk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive session key%s", err.Error())
	}

	resp.E2EE.ClientPK = comm.G1ToBytes(clientPk)
	resp.E2EE.ClientEmpPK = comm.G1ToBytes(clientEmpPk)
	resp.E2EE.IdPEmpKeyId = serverEmpResp.KID
	resp.E2EE.Msg = msgEnc
	return Ks, nil
}

// handleUnblindAuid answers the broker's unblind request: given the blinded AUID
// and the per-session factor k, it returns the recovered uid_rp (paper Fig.6).
func (s *RPServer) handleUnblindAuid(c *fiber.Ctx) error {
	req := protocol.UnblindAuidRequest{}
	if err := c.BodyParser(&req); err != nil {
		return s.handleError(c, comm.BadRequest, "failed to parse unblind request: "+err.Error())
	}
	if req.AUID == "" || len(req.K) == 0 {
		return s.handleError(c, comm.BadRequest, "missing auid or k")
	}
	k, err := comm.BytesToScalar(req.K)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "invalid k: "+err.Error())
	}
	uidRp, err := unblindAuid(req.AUID, k)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "failed to unblind auid: "+err.Error())
	}
	return c.JSON(protocol.UnblindAuidResponse{UIDRP: uidRp})
}

// unblindAuid removes the broker's per-session factor k from the AUID, yielding
// uid_rp = auid^{1/k}.
func unblindAuid(auid string, k *bls12381.Scalar) (string, error) {
	if k == nil {
		return "", errors.New("missing randomization factor k")
	}
	auidPoint, err := comm.StringToG1(auid)
	if err != nil {
		return "", err
	}
	var kInv bls12381.Scalar
	kInv.Inv(k)
	var uidrp bls12381.G1
	uidrp.ScalarMult(&kInv, auidPoint)
	return comm.G1ToString(&uidrp), nil
}

// handleCallback completes the login: it checks the OAuth state, redeems the
// broker's code for tokens, and decrypts the K_S-protected identity claims that
// neither the broker nor anyone else on the path could read.
func (s *RPServer) handleCallback(c *fiber.Ctx) error {
	sess, err := s.sessions.Get(c)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "Failed to get session"+err.Error())
	}
	state := c.Query("state")
	savedState, ok := sess.Get("state").(string)
	if !ok || savedState == "" {
		return s.handleError(c, comm.BadRequest, "no state on session — login flow not initiated by this browser")
	}
	if state != savedState {
		return s.handleError(c, comm.BadRequest, "state mismatch — possible CSRF")
	}

	code := c.Query("code")
	if code == "" {
		return s.handleError(c, comm.BadRequest, "code is empty")
	}

	tokenResp, err := requestTokenFromBroker(s, c, code)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "failed to request token from broker"+err.Error())
	}
	accessToken := tokenResp.AccessToken
	idToken := tokenResp.IdToken

	aakeState, ok := s.store.GetAAKEState(state)
	if !ok {
		return s.handleError(c, comm.BadRequest, "AAKE state not found")
	}
	Ks := aakeState.Ks
	user := rpUser{
		UID:         tokenResp.UIDRP,
		Username:    "",
		Sub:         "",
		AccessToken: accessToken,
	}

	if idToken != "" {
		claims, err := s.VerifyIDToken(idToken)
		if err != nil {
			log.Printf("[ERROR/RP] Failed to verify id_token: %v", err)
			return c.Status(http.StatusUnauthorized).SendString("invalid id_token")
		}
		if encSub, ok := claims["sub"].(string); ok && encSub != "" {
			sub, err := lib.AESDecryptString(Ks, encSub)
			if err != nil {
				log.Printf("[ERROR/RP] Failed to decrypt sub: %v", err)
				return c.Status(http.StatusInternalServerError).SendString("failed to decrypt sub")
			}
			user.Sub = sub
		}
		if encName, ok := claims["name"].(string); ok && encName != "" {
			name, err := lib.AESDecryptString(Ks, encName)
			if err != nil {
				log.Printf("[ERROR/RP] Failed to decrypt name: %v", err)
				return c.Status(http.StatusInternalServerError).SendString("failed to decrypt name")
			}
			user.Username = name
		}
		if encEmail, ok := claims["email"].(string); ok && encEmail != "" {
			email, err := lib.AESDecryptString(Ks, encEmail)
			if err != nil {
				log.Printf("[ERROR/RP] Failed to decrypt email: %v", err)
				return c.Status(http.StatusInternalServerError).SendString("failed to decrypt email")
			}
			user.Email = email
		}
	}
	s.store.SaveUserState(user.UID, &RPUserState{
		User:        user,
		Ks:          Ks,
		AccessToken: []byte(accessToken),
	})
	sess.Set("rpuser", user)
	if err := sess.Save(); err != nil {
		return err
	}
	log.Printf("[INFO/RP] Received tokens via broker; decrypted userinfo with K_S (user=%s)", user.Username)

	next := c.Query("next")
	startTime := c.Query("startTime")
	if next == "" {
		next = "/ssso/home"
	}
	next += "?startTime=" + url.QueryEscape(startTime)
	return c.Redirect(next)
}

// geneatePoK builds the AAKA Σ-protocol proof: it randomizes the RP's
// SecretCredential, commits to the domain and identity secret, derives the
// Fiat-Shamir challenge and returns the proof plus the ephemeral key pair the
// X3DH step binds to.
func geneatePoK(s *RPServer, req *protocol.AAKEGenPoKRequest) (*protocol.AAKEGenPoKResponse, *bls12381.Scalar, *bls12381.G1, error) {
	if req.RSig1 == nil || req.T == nil {
		return nil, nil, nil, errors.New("invalid request body: rSig1, k, t are required")
	}
	rsigma1 := &lib.PSSignMsg{}
	if err := rsigma1.FromJSON(req.RSig1); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid rSig1: %w", err)
	}
	rSignElement1, err := comm.BytesToScalar(req.T)
	if err != nil {
		return nil, nil, nil, err
	}
	rsigma2, _, rSignElement2, err := lib.RandomizeSig(s.SecretCred.SigmaBar)
	if err != nil {
		return nil, nil, nil, err
	}

	var rQpkElement bls12381.Scalar
	if err := rQpkElement.Random(rand.Reader); err != nil {
		return nil, nil, nil, err
	}
	var eQpk bls12381.G1
	var eQsk bls12381.Scalar

	eQsk.Mul(s.IdentitySk, &rQpkElement)
	eQpk.ScalarMult(&eQsk, bls12381.G1Generator())

	var rD, rQsk bls12381.Scalar
	if err := rD.Random(rand.Reader); err != nil {
		return nil, nil, nil, err
	}
	if err := rQsk.Random(rand.Reader); err != nil {
		return nil, nil, nil, err
	}

	var C1 bls12381.G2
	var domainScalar bls12381.Scalar
	domainScalar.SetBytes(s.Domain)
	C1.ScalarMult(rSignElement1, bls12381.G2Generator())
	var tmpG2 bls12381.G2
	tmpG2.ScalarMult(&domainScalar, s.ServerCredPk.Vk1.Yhatn[0])
	C1.Add(&C1, &tmpG2)

	var r1 bls12381.Scalar
	if err := r1.Random(rand.Reader); err != nil {
		return nil, nil, nil, err
	}
	var R1 bls12381.G2
	R1.ScalarMult(&r1, bls12381.G2Generator())
	tmpG2.ScalarMult(&rD, s.ServerCredPk.Vk1.Yhatn[0])
	R1.Add(&R1, &tmpG2)

	var C2 bls12381.G2
	C2.ScalarMult(rSignElement2, bls12381.G2Generator())
	tmpG2.ScalarMult(&domainScalar, s.ServerCredPk.Vk2.Yhatn[0])
	C2.Add(&C2, &tmpG2)
	tmpG2.ScalarMult(s.IdentitySk, s.ServerCredPk.Vk2.Yhatn[1])
	C2.Add(&C2, &tmpG2)

	var r2 bls12381.Scalar
	if err := r2.Random(rand.Reader); err != nil {
		return nil, nil, nil, err
	}
	var R2 bls12381.G2
	R2.ScalarMult(&r2, bls12381.G2Generator())
	tmpG2.ScalarMult(&rD, s.ServerCredPk.Vk2.Yhatn[0])
	R2.Add(&R2, &tmpG2)
	tmpG2.ScalarMult(&rQsk, s.ServerCredPk.Vk2.Yhatn[1])
	R2.Add(&R2, &tmpG2)

	C3 := eQpk
	var r3 bls12381.Scalar
	if err := r3.Random(rand.Reader); err != nil {
		return nil, nil, nil, err
	}
	var R3 bls12381.G1
	var tmp2 bls12381.Scalar
	tmp2.Mul(s.IdentitySk, &r3)
	R3.ScalarMult(&tmp2, bls12381.G1Generator())

	hsh := sha256.New()
	for _, y := range s.ServerCredPk.Vk1.Yhatn {
		hsh.Write(y.BytesCompressed())
	}
	for _, y := range s.ServerCredPk.Vk2.Yhatn {
		hsh.Write(y.BytesCompressed())
	}
	hsh.Write(C1.BytesCompressed())
	hsh.Write(C2.BytesCompressed())
	hsh.Write(C3.BytesCompressed())
	hsh.Write(R1.BytesCompressed())
	hsh.Write(R2.BytesCompressed())
	hsh.Write(R3.BytesCompressed())

	var c bls12381.Scalar
	c.SetBytes(hsh.Sum(nil))

	var zD, zQsk, z1, z2, z3 bls12381.Scalar
	zD.Mul(&c, &domainScalar)
	zD.Add(&zD, &rD)

	zQsk.Mul(&c, s.IdentitySk)
	zQsk.Add(&zQsk, &rQsk)

	z1.Mul(&c, rSignElement1)
	z1.Add(&z1, &r1)

	z2.Mul(&c, rSignElement2)
	z2.Add(&z2, &r2)

	z3.Mul(&c, &rQpkElement)
	z3.Add(&z3, &r3)
	z3.Mul(&z3, s.IdentitySk)
	zDBytes, _ := zD.MarshalBinary()
	zQskBytes, _ := zQsk.MarshalBinary()
	z1Bytes, _ := z1.MarshalBinary()
	z2Bytes, _ := z2.MarshalBinary()
	z3Bytes, _ := z3.MarshalBinary()

	sign1Bytes, err := rsigma1.ToJSON()
	if err != nil {
		return nil, nil, nil, err
	}
	sign2Bytes, err := rsigma2.ToJSON()
	if err != nil {
		return nil, nil, nil, err
	}
	resp := &protocol.AAKEGenPoKResponse{
		Sign1: sign1Bytes,
		Sign2: sign2Bytes,
		C:     protocol.CGroup{C1: C1.BytesCompressed(), C2: C2.BytesCompressed(), C3: C3.BytesCompressed()},
		R:     protocol.RGroup{R1: R1.BytesCompressed(), R2: R2.BytesCompressed(), R3: R3.BytesCompressed()},
		Z:     protocol.ZGroup{ZD: zDBytes, ZQsk: zQskBytes, Z1: z1Bytes, Z2: z2Bytes, Z3: z3Bytes},
	}
	return resp, &eQsk, &eQpk, nil
}

// x3KeyExchangeRP computes the three X3DH shared secrets from the RP's side,
// pairing its identity and ephemeral keys against the IdP's.
func x3KeyExchangeRP(sk1 *bls12381.Scalar, sk2 *bls12381.Scalar, pk1 *bls12381.G1, pk2 *bls12381.G1) (dh1, dh2, dh3 []byte, err error) {
	if sk1 == nil || pk1 == nil || sk2 == nil || pk2 == nil {
		return nil, nil, nil, errors.New("sk or pk is nil")
	}
	dh1, err = lib.DH(sk1, pk2)
	if err != nil {
		return nil, nil, nil, err
	}
	dh2, err = lib.DH(sk2, pk1)
	if err != nil {
		return nil, nil, nil, err
	}
	dh3, err = lib.DH(sk2, pk2)
	if err != nil {
		return nil, nil, nil, err
	}

	return dh1, dh2, dh3, nil
}

// newSession runs X3DH against the IdP's keys and returns the session key K_S,
// the RP's ephemeral public key, and the key-confirmation ciphertext.
func newSession(clientSk *bls12381.Scalar, clientPk *bls12381.G1, serverPk *bls12381.G1, serverEmpPk *bls12381.G1) (sessionKey []byte, clientEmpPk *bls12381.G1, msgEnc []byte, err error) {
	clientEmpSk, clientEmpPk := lib.GenerateEmpKey()

	dh1, dh2, dh3, err := x3KeyExchangeRP(clientSk, clientEmpSk, serverPk, serverEmpPk)
	if err != nil {
		return nil, nil, nil, errors.New("failed to exchange keys")
	}
	tempSessionKey, err := lib.DeriveSessionKey(dh1, dh2, dh3)
	if err != nil {
		return nil, nil, nil, errors.New("failed to derive session key")
	}
	aad := append(clientPk.BytesCompressed(), serverPk.BytesCompressed()...)
	msg := append(clientEmpPk.BytesCompressed(), serverEmpPk.BytesCompressed()...)
	msgEnc, err = lib.AesGcmEncrypt(tempSessionKey, msg, aad)
	if err != nil {
		return nil, nil, nil, errors.New("failed to derive session key, can't encrypt msgInit")
	}
	return tempSessionKey, clientEmpPk, msgEnc, nil
}

// requestTokenFromBroker exchanges the broker's authorization code for the
// tokens and the RP-local pseudonym uid_rp.
func requestTokenFromBroker(s *RPServer, c *fiber.Ctx, code string) (*protocol.AAKETokenToRPResponse, error) {
	request := &protocol.AAKETokenFromRPRequest{
		GrantType: "authorization_code",
		Code:      code,
	}
	resp := &protocol.AAKETokenToRPResponse{}
	err := s.sendPostRequest(c.Context(), s.config.BrokerTokenURL, request, http.StatusOK, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
