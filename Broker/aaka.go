// Broker side of the AAKA exchange: relays PoK and token requests between RP
// and IdP, and issues the authorization code.
package broker

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
)

// handleTokenFromIdP drives the AAKA generation phase: it fetches the PoK from
// the RP, exchanges it with the IdP for tokens, has the RP unblind the AUID, and
// issues an authorization code back to the RP.
func (s *BrokerServer) handleTokenFromIdP(c *fiber.Ctx) error {
	sessionID := c.FormValue("session_id")
	code := c.FormValue("code")
	if sessionID == "" || code == "" {
		return s.handleError(c, comm.BadRequest, "session_id not found")
	}

	sData, ok := s.store.sessionData[sessionID]
	if !ok || sData == nil {
		log.Printf("[ERROR/Broker] Session data not found for session_id: %s", sessionID)
		return s.handleError(c, comm.BadRequest, "session data not found or invalid")
	}

	rpData := s.store.rpIdentity[sData.tid]

	log.Printf("[INFO/Broker] Consent code received; pulling AAKA proof from RP and redeeming it at IdP for tokens")

	pok, err := requestPOKFromRP(s, c, sData)
	if err != nil {
		log.Printf("[ERROR/Broker] Failed to request PoK from RP: %s", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to request PoK from RP")
	}

	tokenResp, err := requestTokenFromIdP(s, c, pok, code)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "Failed to request token from IdP"+err.Error())
	}
	Auid := tokenResp.AUID
	uidRp, err := requestUnblindFromRP(s, c, sData, Auid)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "Failed to unblind AUID via RP"+err.Error())
	}
	log.Printf("[INFO/Broker] RP unblinded auid → uid_rp (per-RP pseudonym for routing; unlinkable across RPs)")
	tokens := &Tokens{
		AccessToken:  tokenResp.AccessToken,
		IDToken:      tokenResp.IdToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
	}

	reSignedTokens, err := s.tokenHelper.resignTokensWithBrokerKey(s.config.IdPJWKSURL, tokens)
	if err != nil {
		log.Printf("[ERROR/Broker] Failed to re-sign tokens with broker key: %s", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to re-sign tokens")
	}

	code2, err := s.store.codes.IssueCode(uidRp, sData.tid, reSignedTokens)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "Failed to issue code"+err.Error())
	}

	redirectURL := rpData.CallbackURL + "?code=" + url.QueryEscape(code2) +
		"&state=" + url.QueryEscape(sData.state)

	delete(s.store.sessionData, sessionID)

	c.Status(fiber.StatusOK)
	return c.Redirect(redirectURL)
}

// handleTokenFromBroker redeems the broker-issued authorization code for the
// stored tokens, binds them to the RP's user store, and burns the code.
func (s *BrokerServer) handleTokenFromBroker(c *fiber.Ctx) error {
	req := &protocol.AAKETokenFromRPRequest{}
	if err := s.getRequest(c, req); err != nil {
		return s.handleError(c, comm.BadRequest, "invalid request body"+err.Error())
	}
	code := req.Code
	codeData, err := s.store.codes.GetCode(code)
	if err != nil {
		return s.handleError(c, comm.Unauthorized, "invalid code"+err.Error())
	}

	rpInfo, ok := s.store.rpIdentity[codeData.RPID]
	if !ok || rpInfo == nil {
		return s.handleError(c, comm.NotFound, "RP not found for RPID: "+codeData.RPID)
	}
	if rpInfo.UserStore == nil {
		rpInfo.UserStore = NewUserStore()
	}

	user := &User{
		UID:   codeData.UserID,
		Token: codeData.Tokens,
	}
	rpInfo.UserStore.SaveUser(user)

	s.store.codes.DeleteCode(code)

	resp := protocol.AAKETokenToRPResponse{
		UIDRP:       codeData.UserID,
		IdToken:     codeData.Tokens.IDToken,
		AccessToken: codeData.Tokens.AccessToken,
		TokenType:   codeData.Tokens.TokenType,
	}
	return c.JSON(resp)

}

// requestPOKFromRP asks the RP to prove knowledge of its SecretCredential
// against the randomized signature held for this session.
func requestPOKFromRP(s *BrokerServer, c *fiber.Ctx, sData *brokerSessionData) (resp *protocol.AAKEGenPoKResponse, err error) {
	rSig1Bytes, err := sData.randSig.ToJSON()
	if err != nil {
		return nil, err
	}
	request := &protocol.AAKEGenPoKRequest{
		State: sData.state,
		RSig1: rSig1Bytes,
		T:     comm.ScalarToBytes(sData.t),
	}
	resp = &protocol.AAKEGenPoKResponse{}
	err = s.sendPostRequest(c, s.config.RPPoKURL, request, http.StatusOK, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// requestTokenFromIdP forwards the RP's PoK plus the user's consent code to the
// IdP and returns the issued tokens and the blinded auid.
func requestTokenFromIdP(s *BrokerServer, c *fiber.Ctx, pok *protocol.AAKEGenPoKResponse, code string) (*protocol.AAKETokenResponse, error) {
	req := &protocol.AAKETokenRequest{
		Sign1: pok.Sign1,
		Sign2: pok.Sign2,
		C:     pok.C,
		R:     pok.R,
		Z:     pok.Z,
		E2EE:  pok.E2EE,
		Code:  code,
	}
	resp := &protocol.AAKETokenResponse{}
	err := s.sendPostRequest(c, s.config.IdPTokenURL, req, http.StatusOK, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// requestUnblindFromRP forwards (auid, k) to the RP and returns the uid_rp it
// recovers, which the broker stores for per-(RP,user) routing (paper Fig.6).
func requestUnblindFromRP(s *BrokerServer, c *fiber.Ctx, sData *brokerSessionData, auid string) (string, error) {
	req := &protocol.UnblindAuidRequest{
		AUID: auid,
		K:    comm.ScalarToBytes(sData.k),
	}
	resp := &protocol.UnblindAuidResponse{}
	if err := s.sendPostRequest(c, s.config.RPUnblindURL, req, http.StatusOK, resp); err != nil {
		return "", err
	}
	if resp.UIDRP == "" {
		return "", errors.New("RP returned empty uid_rp")
	}
	return resp.UIDRP, nil
}

// GetUnblindAuid removes the per-session blinding factor k from an AUID,
// yielding uid_RP. Used by the in-process local-overhead benchmark; the live
// protocol performs the unblind on the RP side.
func GetUnblindAuid(Auid string, k *bls12381.Scalar) (string, error) {
	auidBytes, err := comm.StringToG1(Auid)
	if err != nil {
		return "", err
	}
	if k == nil {
		return "", errors.New("randomization parameter 'k' is not available")
	}
	var kInv bls12381.Scalar
	kInv.Inv(k)
	var uidrp bls12381.G1
	uidrp.ScalarMult(&kInv, auidBytes)
	return comm.G1ToString(&uidrp), nil
}
