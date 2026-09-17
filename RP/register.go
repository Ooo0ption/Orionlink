// RP registration flows: the register exchanges with the IdP and the Broker, and
// the credential material they produce.
package rp

import (
	"context"
	"errors"
	"fmt"
	"log"
	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
)

// Scopes is the fixed scope set this RP requests at registration.
var Scopes = []string{"username", "email", "sub", "offline_access"}

// registerToIdP runs the RP to IdP registration (paper Fig.4), independent of any
// HTTP request so both the handler and startup auto-registration can drive it.
func (s *RPServer) registerToIdP(ctx context.Context) error {
	var request protocol.RPRegisterToIdPRequest
	d, err := s.getRegisterRequestToIdP(&request)
	if err != nil {
		return fmt.Errorf("prepare cred1: %w", err)
	}
	var resp protocol.RPRegisterToIdPResponse
	err = s.sendPostRequest(
		ctx,
		s.config.IdPRegisterURL,
		request,
		comm.StatusCreated,
		&resp,
	)
	if err != nil {
		return fmt.Errorf("IdP communication failed: %w", err)
	}
	if err := s.getCredential(&resp, d); err != nil {
		return fmt.Errorf("get credential: %w", err)
	}
	log.Printf("[INFO/RP] RP registered to IdP successfully.")
	return nil
}

// handleRegisterIdP runs the IdP registration on request and returns the
// resulting DomainCred and SecretCred for the registration page to display.
func (s *RPServer) handleRegisterIdP(c *fiber.Ctx) error {
	if err := s.registerToIdP(c.Context()); err != nil {
		return s.handleError(c, comm.ServerError, "RP registration to IdP failed: "+err.Error())
	}
	c.Status(fiber.StatusOK)

	var sigmaBytes, sigmaBarBytes []byte
	var identitySkBytes []byte

	if s.DomainCred.Sigma != nil {
		sigmaBytes, _ = s.DomainCred.Sigma.ToJSON()
	}
	if s.SecretCred.SigmaBar != nil {
		sigmaBarBytes, _ = s.SecretCred.SigmaBar.ToJSON()
	}
	if s.SecretCred.IdentitySk != nil {
		identitySkBytes = comm.ScalarToBytes(s.SecretCred.IdentitySk)
	}

	return c.JSON(fiber.Map{
		"DomainCred": fiber.Map{
			"Domain": s.DomainCred.Domain,
			"Sigma":  sigmaBytes,
		},
		"SecretCred": fiber.Map{
			"Domain":     s.SecretCred.Domain,
			"IdentitySk": identitySkBytes,
			"SigmaBar":   sigmaBarBytes,
		},
	})
}

// registerToBroker runs the RP to Broker registration, independent of any HTTP
// request so both the handler and startup auto-registration can drive it.
func (s *RPServer) registerToBroker(ctx context.Context) (string, error) {
	var request protocol.RPRegisterToBrokerRequest
	err := s.getRegisterRequestToBroker(&request)
	if err != nil {
		return "", fmt.Errorf("build register request: %w", err)
	}

	var resp protocol.RPRegisterToBrokerResponse
	err = s.sendPostRequest(
		ctx,
		s.config.BrokerRegisterURL,
		request,
		comm.StatusCreated,
		&resp,
	)
	if err != nil {
		return "", fmt.Errorf("Broker communication failed: %w", err)
	}
	s.TID = resp.TID
	log.Printf("[INFO/RP] RP registered to Broker successfully.")

	if err := s.saveRegistrationData(); err != nil {
		log.Printf("[WARNING/RP] Failed to save registration data: %v", err)
	}
	return resp.TID, nil
}

// handleRegisterBroker runs the broker registration on request and returns the
// assigned tid.
func (s *RPServer) handleRegisterBroker(c *fiber.Ctx) error {
	tid, err := s.registerToBroker(c.Context())
	if err != nil {
		return s.handleError(c, comm.ServerError, "RP registration to Broker failed: "+err.Error())
	}
	c.Status(fiber.StatusOK)
	return c.JSON(fiber.Map{"tid": tid})
}

// getRegisterRequestToIdP builds the registration request: it commits to the RP's
// identity secret for blind signing and returns the blinding factor d needed to
// unblind the IdP's response.
func (s *RPServer) getRegisterRequestToIdP(request *protocol.RPRegisterToIdPRequest) (d *bls12381.Scalar, err error) {
	vkIK := *s.ServerCredPk.Vk2.Yn[1]
	proof, d, err := lib.PrepareBlindSign([]*bls12381.Scalar{s.IdentitySk}, []*bls12381.G1{&vkIK})
	if err != nil {
		return nil, errors.New("prepare blind sign failed")
	}
	var zsBytes [][]byte
	for _, z := range proof.Zs {
		zsBytes = append(zsBytes, comm.ScalarToBytes(z))
	}

	request.Domain = s.Domain
	request.C1 = comm.G1ToBytes(proof.C1)
	request.R1 = comm.G1ToBytes(proof.R1)
	request.Z0 = comm.ScalarToBytes(proof.Z0)
	request.Zs = zsBytes
	return d, nil
}

// getCredential unblinds the IdP's response into the RP's final DomainCred and
// SecretCred.
func (s *RPServer) getCredential(resp *protocol.RPRegisterToIdPResponse, d *bls12381.Scalar) (err error) {

	s.DomainCred.Sigma = &lib.PSSignMsg{}
	err = s.DomainCred.Sigma.FromJSON(resp.Sig1)
	if err != nil {
		return errors.New("failed to unmarshal sigma: " + err.Error())
	}
	s.SecretCred.SigmaBar = &lib.PSSignMsg{}
	err = s.SecretCred.SigmaBar.FromJSON(resp.BlindSig2)
	if err != nil {
		return errors.New("failed to unmarshal sigma bar: " + err.Error())
	}
	s.SecretCred.SigmaBar, err = lib.Unblind(s.SecretCred.SigmaBar, d)
	s.SecretCred.IdentitySk = s.IdentitySk
	if err != nil {
		return err
	}

	var domainScalar bls12381.Scalar
	domainScalar.SetBytes(s.Domain)

	ok := lib.PSVerify(s.DomainCred.Sigma, []*bls12381.Scalar{&domainScalar}, s.ServerCredPk.Vk1)
	if !ok {
		return errors.New("PSVerify failed for Sign1")
	}
	ok = lib.PSVerify(s.SecretCred.SigmaBar, []*bls12381.Scalar{&domainScalar, s.SecretCred.IdentitySk}, s.ServerCredPk.Vk2)
	if !ok {
		return errors.New("PSVerify failed for Sign2")
	}
	return nil
}

// getRegisterRequestToBroker builds the broker registration request from the
// RP's DomainCred, callback URL, scopes and refresh prekeys.
func (s *RPServer) getRegisterRequestToBroker(request *protocol.RPRegisterToBrokerRequest) (err error) {
	sig1Bytes, err := s.DomainCred.Sigma.ToJSON()
	if err != nil {
		return err
	}
	request.Sig1 = sig1Bytes
	request.Domain = s.Domain
	request.Scopes = Scopes
	request.CallbackURL = s.config.RedirectURI
	if s.refreshHelper != nil {
		request.RPDHPks = s.refreshHelper.PublicKeys()
	}
	return nil
}
