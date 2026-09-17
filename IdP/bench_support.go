// Measurement scaffolding for the IdP: synthetic account seeding, load-test
// endpoints, and the exported wrappers the benchmark packages need.
package idp

import (
	"errors"
	"fmt"
	"log"
	"os"
	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/internal/protocol"
	"secure-sso/lib"
	"strconv"

	"github.com/cloudflare/circl/group"
	"github.com/gofiber/fiber/v2"
)

// defaultBenchUsers is the number of synthetic accounts seeded under the bench
// profile.
const defaultBenchUsers = 1000

// SeedBenchUsers generates the synthetic accounts load tests drive, so that
// concurrent virtual users do not serialise on a single account. The count is
// overridable with ORION_BENCH_USERS.
func (s *tempStorageService) SeedBenchUsers(cfg *orionconf.Config) {
	if !cfg.IsBench() {
		return
	}

	n := defaultBenchUsers
	if raw := os.Getenv("ORION_BENCH_USERS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			log.Printf("[WARN/IdP] ORION_BENCH_USERS=%q is not a non-negative integer; using %d", raw, n)
		} else {
			n = parsed
		}
	}

	for i := 0; i < n; i++ {
		username := fmt.Sprintf("bench%06d", i)
		if _, exists := s.users[username]; exists {
			continue
		}
		s.users[username] = &User{
			Username: username,
			Password: username + "-pass",
			Sub:      fmt.Sprintf("9%06d", i),
			Email:    username + "@bench.invalid",
		}
	}
	log.Printf("[INFO/IdP] profile=bench: seeded %d synthetic users (ORION_BENCH_USERS)", n)
}

// stressTestUID is the fixed account the load-test token endpoint issues for.
const stressTestUID = "902988"

// handleTokenForTest runs the token endpoint's crypto path (PoK verification,
// K_S derivation, token issuance) against a fixed user, skipping the consent
// code so load tests can hammer it directly.
func (s *IdPServer) handleTokenForTest(c *fiber.Ctx) error {
	req := &protocol.AAKETokenRequest{}
	if err := s.getRequest(c, req); err != nil {
		return s.handleError(c, comm.BadRequest, "invalid request body "+err.Error())
	}

	proof, err := toProof(req)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "invalid proof "+err.Error())
	}
	if ok, err := verifyPoK(s, proof); !ok {
		return s.handleError(c, comm.Unauthorized, "invalid proof "+err.Error())
	}

	edata, err := toE2eeData(req)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "invalid e2ee data "+err.Error())
	}
	sessionKey, err := getSessionKey(s, edata)
	if err != nil {
		return s.handleError(c, comm.Unauthorized, "session key derivation failed "+err.Error())
	}

	uid := lib.HashStringToScalar(stressTestUID)
	auid := GenerateAuid(proof.Sign1.Sigma1, uid)
	auidStr := comm.G1ToString(auid)

	data := &authorizedUserData{
		acid:     auidStr,
		uid:      stressTestUID,
		username: "Alice",
		email:    "Alice@example.com",
		scope:    "openid profile email",
	}
	idToken, accessToken, refreshToken, err := generateTokens(s, data, sessionKey)
	if err != nil {
		return s.handleError(c, comm.ServerError, "failed to generate tokens "+err.Error())
	}

	return c.JSON(protocol.AAKETokenResponse{
		AUID:         auidStr,
		IdToken:      idToken,
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
	})
}

// ProcessRegistrationForTest exposes the RP registration handling to test packages.
func (s *IdPServer) ProcessRegistrationForTest(req *protocol.RPRegisterToIdPRequest) (*protocol.RPRegisterToIdPResponse, error) {
	return getRegisterRespToRP(s, req)
}

// InitTokenAndRefreshForTest initializes the token and refresh helpers, which a
// locally constructed server does not set up.
func (s *IdPServer) InitTokenAndRefreshForTest(issuer string) error {
	if s == nil {
		return errors.New("nil IdPServer")
	}
	if issuer == "" {
		issuer = orionconf.Get().Issuer()
	}
	if s.tokenHelper == nil {
		s.tokenHelper = NewTokenHelper()
		if s.tokenHelper == nil {
			return errors.New("failed to init token helper")
		}
		s.tokenHelper.Issuer = issuer
	}
	if s.refreshHelper == nil {
		s.refreshHelper = NewIdPRefreshTokenHelper(s.tokenHelper)
	}
	return nil
}

// GenerateRefreshTokenForTest mints a valid refresh token.
func (s *IdPServer) GenerateRefreshTokenForTest(userID, scope, audience string) (string, error) {
	if err := s.InitTokenAndRefreshForTest(orionconf.Get().Issuer()); err != nil {
		return "", err
	}
	return s.tokenHelper.GenerateRefreshToken(userID, scope, audience)
}

// RefreshFromBrokerForTest runs the refresh endpoint logic without HTTP.
func (s *IdPServer) RefreshFromBrokerForTest(req *protocol.RefreshTokenFromBrokerRequest) (*protocol.RefreshTokenToRPResponse, error) {
	if s == nil {
		return nil, errors.New("nil IdPServer")
	}
	if s.refreshHelper == nil {
		return nil, errors.New("refresh helper not initialized")
	}
	return s.refreshHelper.HandleBrokerRequest(req)
}

// GetIdPEmpKeyForTest returns an IdP ephemeral key (kid + pk) without going
// through the HTTP handler.
func (s *IdPServer) GetIdPEmpKeyForTest() (*protocol.IdPEmpKeyResponse, error) {
	if s.store == nil || s.store.empkeys == nil {
		return nil, errors.New("idp store/empkeys not initialized")
	}
	if len(s.store.empkeys.keys) == 0 {
		s.store.empkeys.keys = make(map[string]*comm.AAKEEphemeralKey, 100)
		s.store.EmpKeyIdx = 0

		for i := 0; i < 100; i++ {
			sk, pk := lib.GenerateEmpKey()
			s.store.empkeys.keys[strconv.Itoa(i)] = &comm.AAKEEphemeralKey{
				ID: fmt.Sprintf("%d", i),
				SK: sk,
				PK: pk,
			}
		}
	}
	if s.store.EmpKeyIdx >= len(s.store.empkeys.keys) {
		s.store.EmpKeyIdx = 0
	}
	idStr := strconv.Itoa(s.store.EmpKeyIdx)
	key, err := s.store.empkeys.getEmpKey(idStr)
	if err != nil {
		return nil, err
	}
	s.store.EmpKeyIdx++
	return &protocol.IdPEmpKeyResponse{
		KID: idStr,
		PK:  comm.G1ToBytes(key.PK),
	}, nil
}

// NewSessionForTest derives the AAKA session key from E2EE parameters without
// running the full token issuance flow.
func (s *IdPServer) NewSessionForTest(e2ee protocol.E2EE) ([]byte, error) {
	req := &protocol.AAKETokenRequest{E2EE: e2ee}
	edata, err := toE2eeData(req)
	if err != nil {
		return nil, err
	}
	return getSessionKey(s, edata)
}

// GetEmpKeyForTest looks up a stored ephemeral key by id.
func (s *IdPServer) GetEmpKeyForTest(id string) (*comm.AAKEEphemeralKey, error) {
	return s.store.empkeys.getEmpKey(id)
}

// VerifyPoKForTest exposes the internal PoK verification.
func (s *IdPServer) VerifyPoKForTest(req *protocol.AAKETokenRequest) (bool, error) {
	proof, err := toProof(req)
	if err != nil {
		return false, err
	}
	return verifyPoK(s, proof)
}

// OPRFServerEvaluateForTest exposes the PIN-OPRF server evaluation.
func (s *IdPServer) OPRFServerEvaluateForTest(alpha []byte) ([]byte, error) {
	return s.oprf.ServerEvaluate(alpha)
}

// GetOPRFGroup returns the Ristretto255 group used for OPRF operations.
func (s *IdPServer) GetOPRFGroup() group.Group {
	return s.oprf.Group
}

// GenerateTokensForTest exposes token issuance, returning the three tokens in
// exactly the form the IdP would send them to the broker.
func (s *IdPServer) GenerateTokensForTest(uid, username, email, scope, acid string, ks []byte) (idToken, accessToken, refreshToken string, err error) {
	data := &authorizedUserData{
		uid:      uid,
		username: username,
		email:    email,
		scope:    scope,
		acid:     acid,
	}
	return generateTokens(s, data, ks)
}
