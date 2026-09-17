// Measurement scaffolding for the Broker: load-test endpoints and the exported
// wrappers the benchmark packages need.
package broker

import (
	"errors"
	"net/http"
	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/gofiber/fiber/v2"
)

// handleRandomizeRPIDForTest randomizes the first registered RP's DomainCred and
// returns the resulting (rsign, t), skipping session setup so load tests can
// drive the randomization path directly.
func (s *BrokerServer) handleRandomizeRPIDForTest(c *fiber.Ctx) error {
	var tid string
	for k := range s.store.rpIdentity {
		tid = k
		break
	}
	if tid == "" {
		return s.handleError(c, comm.BadRequest, "no RP registered — register first")
	}
	domainCred := s.store.rpIdentity[tid].DomainCred
	rsign, _, t, err := lib.RandomizeSig(domainCred.Sigma)
	if err != nil {
		return s.handleError(c, comm.ServerError, "randomize sig failed "+err.Error())
	}
	c.Status(http.StatusOK)
	return c.JSON(fiber.Map{
		"sigma1": comm.G1ToString(rsign.Sigma1),
		"sigma2": comm.G1ToString(rsign.Sigma2),
		"t":      comm.BytesToString(comm.ScalarToBytes(t)),
		"tid":    tid,
	})
}

// ProcessRegistrationForTest exposes the RP registration handling to test packages.
func (s *BrokerServer) ProcessRegistrationForTest(req *protocol.RPRegisterToBrokerRequest, resp *protocol.RPRegisterToBrokerResponse) error {
	return getRegisterRespToBroker(s, req, resp)
}

// InitRPIdentityForTest inserts an RP identity record directly, bypassing registration.
func (s *BrokerServer) InitRPIdentityForTest(tid string, rpDHPks [][]byte, uidRp string, refreshToken string) error {
	if s == nil {
		return errors.New("broker not initialized")
	}
	if s.store == nil {
		s.store = NewTempStorageService()
	}
	if s.refreshHelper == nil {
		s.refreshHelper = NewRefreshTokenHelper()
	}
	if tid == "" {
		return errors.New("missing tid")
	}
	if len(rpDHPks) == 0 {
		return errors.New("missing rp dh public keys")
	}
	s.store.rpIdentity[tid] = &rpIdentity{
		TID:       tid,
		UserStore: NewUserStore(),
		RPDHPks:   rpDHPks,
	}
	rpInfo := s.store.rpIdentity[tid]
	if rpInfo == nil || rpInfo.UserStore == nil {
		return errors.New("rp not found for tid")
	}
	rpInfo.UserStore.SaveUser(&User{
		UID: uidRp,
		Token: &Tokens{
			RefreshToken: refreshToken,
		},
	})
	s.refreshHelper.InitForRP(tid, rpDHPks)

	return nil
}

// RefreshWithIdPLocalForTest performs the Broker/IdP refresh relay without HTTP.
func (s *BrokerServer) RefreshWithIdPLocalForTest(req *protocol.RefreshTokenFromRPRequest) (*protocol.RefreshTokenFromBrokerRequest, error) {
	if s == nil {
		return nil, errors.New("broker not initialized")
	}
	if s.store == nil || s.refreshHelper == nil {
		return nil, errors.New("broker not initialized")
	}
	if req == nil {
		return nil, errors.New("missing refresh request")
	}
	rpInfo := s.store.rpIdentity[req.TID]
	if rpInfo == nil || rpInfo.UserStore == nil {
		return nil, errors.New("rp not found for tid")
	}
	user, ok := rpInfo.UserStore.GetUser(req.UIDRP)
	if !ok || user == nil || user.Token == nil || user.Token.RefreshToken == "" {
		return nil, errors.New("refresh token not found for uid")
	}
	state, err := s.refreshHelper.ensureState(req.TID, rpInfo.RPDHPks)
	if err != nil {
		return nil, err
	}
	if int(state.seq) >= len(state.rpDHPks) {
		return nil, errors.New("rp dh key list exhausted")
	}
	reqBroker := &protocol.RefreshTokenFromBrokerRequest{
		Hdr:          state.rpDHPks[state.seq],
		Seq:          state.seq,
		RefreshToken: user.Token.RefreshToken,
	}
	s.refreshHelper.mu.Lock()
	state.seq++
	s.refreshHelper.mu.Unlock()
	return reqBroker, nil
}
