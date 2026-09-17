// Broker handling of RP registration: stores the RP's identity, credential and
// refresh public keys.
package broker

import (
	"crypto/rand"
	"errors"
	"log"
	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/gofiber/fiber/v2"
)

// handleRegisterRP accepts an RP registration and returns the ticket id (tid)
// under which the broker will address that RP.
func (s *BrokerServer) handleRegisterRP(c *fiber.Ctx) error {
	var request protocol.RPRegisterToBrokerRequest
	if err := c.BodyParser(&request); err != nil {
		return s.handleError(c, comm.BadRequest, "invalid request"+err.Error())
	}
	var resp protocol.RPRegisterToBrokerResponse
	if err := getRegisterRespToBroker(s, &request, &resp); err != nil {
		return s.handleError(c, comm.BadRequest, "invalid request"+err.Error())
	}
	log.Printf("[INFO/Broker]RP registration successful. tid: %s", resp.TID)
	c.Status(fiber.StatusCreated)
	return c.JSON(resp)
}

// getRegisterRespToBroker mints a fresh tid, stores the RP's DomainCredential
// and prekeys in memory and on disk, and fills in the response.
func getRegisterRespToBroker(s *BrokerServer, req *protocol.RPRegisterToBrokerRequest, resp *protocol.RPRegisterToBrokerResponse) error {
	tid := make([]byte, 16)
	if _, err := rand.Read(tid); err != nil {
		return errors.New("failed to generate random number")
	}
	tidStr := comm.BytesToString(tid)
	domainCred := &comm.DomainCredential{
		Domain: req.Domain,
		Sigma:  &lib.PSSignMsg{},
	}
	err := domainCred.Sigma.FromJSON(req.Sig1)
	if err != nil {
		return errors.New("failed to unmarshal sigma")
	}
	rpInfo := &rpIdentity{
		TID:         tidStr,
		DomainCred:  domainCred,
		Scopes:      req.Scopes,
		CallbackURL: req.CallbackURL,
		UserStore:   NewUserStore(),
		RPDHPks:     req.RPDHPks,
	}
	s.store.rpIdentity[tidStr] = rpInfo

	if err := s.saveRegistrationData(tidStr, rpInfo); err != nil {
		log.Printf("[WARNING/Broker] Failed to save registration data: %v", err)
	}

	resp.TID = tidStr
	return nil
}
