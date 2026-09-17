// Measurement scaffolding for the RP: startup auto-registration, load-test
// endpoints, and the exported wrappers the benchmark packages need.
package rp

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/internal/protocol"
	"time"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
)

// AutoRegister runs the RP's two registration exchanges (RP to IdP, then RP to
// Broker) at startup when this RP has not registered yet. It is meant for
// unattended runs; failures are logged rather than fatal, and the manual
// registration page stays available.
func (s *RPServer) AutoRegister(cfg *orionconf.Config) {
	if !shouldAutoRegister(cfg) {
		return
	}

	if regData, err := s.loadRegistrationData(); err == nil &&
		regData.IDPRegistered && regData.BrokerRegistered && regData.TID != "" {
		log.Printf("[INFO/RP] already registered (tid=%s); skipping auto-registration", regData.TID)
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		for attempt := 1; attempt <= 10; attempt++ {
			if err := s.registerToIdP(ctx); err != nil {
				log.Printf("[WARN/RP] auto-registration to IdP failed (attempt %d/10): %v", attempt, err)
			} else if _, err := s.registerToBroker(ctx); err != nil {
				log.Printf("[WARN/RP] auto-registration to Broker failed (attempt %d/10): %v", attempt, err)
			} else {
				log.Printf("[INFO/RP] auto-registration complete (tid=%s)", s.TID)
				return
			}

			select {
			case <-ctx.Done():
				log.Printf("[WARN/RP] auto-registration gave up: %v — register manually at %s/ssso/register",
					ctx.Err(), orionconf.Get().RP.Browser)
				return
			case <-time.After(3 * time.Second):
			}
		}
		log.Printf("[WARN/RP] auto-registration exhausted retries — register manually at %s/ssso/register",
			orionconf.Get().RP.Browser)
	}()
}

// shouldAutoRegister reports whether startup registration is enabled: on under
// the bench profile, and forced either way by ORION_AUTO_REGISTER.
func shouldAutoRegister(cfg *orionconf.Config) bool {
	if v := os.Getenv("ORION_AUTO_REGISTER"); v != "" {
		return v == "1" || v == "true"
	}
	return cfg.IsBench()
}

// handleAAKEGenPoKForTest mirrors the PoK endpoint but skips the AAKA-state save,
// so load tests can drive the PoK construction path directly.
func (s *RPServer) handleAAKEGenPoKForTest(c *fiber.Ctx) error {
	req := protocol.AAKEGenPoKRequest{}
	if err := c.BodyParser(&req); err != nil {
		return s.handleError(c, comm.BadRequest, "failed to parse request body "+err.Error())
	}
	resp, _, _, err := geneatePoK(s, &req)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "failed to generate PoK "+err.Error())
	}
	c.Status(http.StatusOK)
	return c.JSON(resp)
}

// handleAAKEGenPoKFixture returns a *complete* M — the PoK plus the E2EE half —
// so a load test can build a valid IdP /ssso/token/test body without touching
// the production endpoint. It is not the RP line's measured path: that is
// handleAAKEGenPoKForTest above, which stays free of the IdP round trip the
// X3DH step needs. Unlike the production handler it neither persists K_S nor
// remembers the session, so calling it leaves no state behind that the refresh
// ratchet or a real login could trip over.
func (s *RPServer) handleAAKEGenPoKFixture(c *fiber.Ctx) error {
	req := protocol.AAKEGenPoKRequest{}
	if err := c.BodyParser(&req); err != nil {
		return s.handleError(c, comm.BadRequest, "failed to parse request body "+err.Error())
	}
	resp, clientSk, clientPk, err := geneatePoK(s, &req)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "failed to generate PoK "+err.Error())
	}
	if _, err := attachE2EE(s, c.Context(), resp, clientSk, clientPk); err != nil {
		return s.handleError(c, comm.BadRequest, err.Error())
	}
	c.Status(http.StatusOK)
	return c.JSON(resp)
}

// PrepareIdPRegistrationForTest exposes construction of the RP to IdP register
// request to test packages.
func (s *RPServer) PrepareIdPRegistrationForTest(request *protocol.RPRegisterToIdPRequest) (*bls12381.Scalar, error) {
	return s.getRegisterRequestToIdP(request)
}

// ProcessCredentialForTest exposes unblinding and storing of the issued credentials.
func (s *RPServer) ProcessCredentialForTest(resp *protocol.RPRegisterToIdPResponse, d *bls12381.Scalar) error {
	return s.getCredential(resp, d)
}

// PrepareBrokerRegistrationForTest exposes construction of the RP to Broker
// register request.
func (s *RPServer) PrepareBrokerRegistrationForTest(request *protocol.RPRegisterToBrokerRequest) error {
	return s.getRegisterRequestToBroker(request)
}

// GeneratePoKForTest exposes the internal PoK generation.
func (s *RPServer) GeneratePoKForTest(req *protocol.AAKEGenPoKRequest) (*protocol.AAKEGenPoKResponse, *bls12381.Scalar, *bls12381.G1, error) {
	return geneatePoK(s, req)
}

// NewSessionForTest exposes the X3DH and E2EE init-message generation.
func (s *RPServer) NewSessionForTest(clientSk *bls12381.Scalar, clientPk *bls12381.G1, serverPk *bls12381.G1, serverEmpPk *bls12381.G1) (sessionKey []byte, clientEmpPk *bls12381.G1, msgEnc []byte, err error) {
	return newSession(clientSk, clientPk, serverPk, serverEmpPk)
}

// DecryptRefreshResponseForTest exposes decryption of a relayed refresh response.
func (s *RPServer) DecryptRefreshResponseForTest(resp *protocol.RefreshTokenToRPResponse) (string, error) {
	if s == nil || s.refreshHelper == nil {
		return "", errors.New("refresh helper not initialized")
	}
	return s.refreshHelper.DecryptResponse(resp)
}

// SetRefreshKeyPairsForTest injects externally generated refresh DH key pairs, so
// a test can hand only the public keys to the broker.
func (s *RPServer) SetRefreshKeyPairsForTest(rsk []*bls12381.Scalar, rpk []*bls12381.G1) error {
	if s == nil {
		return errors.New("nil RPServer")
	}
	if len(rsk) == 0 || len(rpk) == 0 || len(rsk) != len(rpk) {
		return errors.New("invalid refresh key pairs")
	}
	if s.refreshHelper == nil {
		s.refreshHelper = NewRefreshTokenHelper(len(rsk))
	}
	s.refreshHelper.mu.Lock()
	defer s.refreshHelper.mu.Unlock()
	s.refreshHelper.rk = nil
	s.refreshHelper.seeded = false
	s.refreshHelper.ck = nil
	s.refreshHelper.dhB = nil
	s.refreshHelper.rsk = rsk
	s.refreshHelper.rpk = rpk
	return nil
}
